package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	EvtSubscribeToFutureEvents = 1
	evtSubscribeActionError    = 0
	evtSubscribeActionDeliver  = 1
	evtRenderEventXML          = 1
)

var (
	modwevtapi       = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtSubscribe = modwevtapi.NewProc("EvtSubscribe")
	procEvtRender    = modwevtapi.NewProc("EvtRender")
	procEvtClose     = modwevtapi.NewProc("EvtClose")
)

type Event struct {
	XMLName   xml.Name     `xml:"Event"`
	System    SystemData   `xml:"System"`
	EventData []*EventData `xml:"EventData>Data"`
}

type EventData struct {
	Key   string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

type ProviderData struct {
	ProviderName string `xml:"Name,attr"`
	ProviderGUID string `xml:"Guid,attr"`
}

type TimeCreatedData struct {
	SystemTime string `xml:"SystemTime,attr"`
}

type CorrelationData struct {
	ActivityID string `xml:"ActivityID,attr"`
}

type ExecutionData struct {
	ProcessID int `xml:"ProcessID,attr"`
	ThreadID  int `xml:"ThreadID,attr"`
}

type SecurityData struct{}

type SystemData struct {
	Provider      ProviderData    `xml:"Provider"`
	EventID       int             `xml:"EventID"`
	Version       int             `xml:"Version"`
	Level         int             `xml:"Level"`
	Task          int             `xml:"Task"`
	Opcode        int             `xml:"Opcode"`
	Keywords      string          `xml:"Keywords"`
	TimeCreated   TimeCreatedData `xml:"TimeCreated"`
	EventRecordID int64           `xml:"EventRecordID"`
	Correlation   CorrelationData `xml:"Correlation"`
	Execution     ExecutionData   `xml:"Execution"`
	Channel       string          `xml:"Channel"`
	Computer      string          `xml:"Computer"`
	Security      SecurityData    `xml:"Security"`
}

type EventJSON struct {
	Timestamp     string                 `json:"timestamp"`
	ProviderName  string                 `json:"provider_name"`
	ProviderGUID  string                 `json:"provider_guid"`
	EventID       int                    `json:"event_id"`
	Version       int                    `json:"version"`
	Level         int                    `json:"level"`
	Task          int                    `json:"task"`
	Opcode        int                    `json:"opcode"`
	Keywords      string                 `json:"keywords"`
	TimeCreated   string                 `json:"time_created"`
	EventRecordID int64                  `json:"record_id"`
	Correlation   CorrelationData        `json:"correlation"`
	Execution     ExecutionData          `json:"execution"`
	Channel       string                 `json:"channel"`
	Computer      string                 `json:"computer"`
	EventData     map[string]interface{} `json:"data"`
}

type EventCallback func(event *Event)

type EventSubscription struct {
	Channel         string
	Query           string
	SubscribeMethod int
	Errors          chan error
	Callback        EventCallback
	winAPIHandle    windows.Handle
}

func (evtSub *EventSubscription) Create() error {
	if evtSub.winAPIHandle != 0 {
		return fmt.Errorf("windows_events: subscription has already been created")
	}

	winChannel, err := windows.UTF16PtrFromString(evtSub.Channel)
	if err != nil {
		return fmt.Errorf("windows_events: invalid channel name: %s", err)
	}

	winQuery, err := windows.UTF16PtrFromString(evtSub.Query)
	if err != nil {
		return fmt.Errorf("windows_events: invalid query: %s", err)
	}

	callback := syscall.NewCallback(evtSub.winAPICallback)

	// Debug logging
	log.Printf("Debug - Subscribing to channel: %s", evtSub.Channel)

	handle, _, err := procEvtSubscribe.Call(
		0,
		0,
		uintptr(unsafe.Pointer(winChannel)),
		uintptr(unsafe.Pointer(winQuery)),
		0,
		0,
		callback,
		uintptr(EvtSubscribeToFutureEvents),
	)

	if handle == 0 {
		return fmt.Errorf("windows_events: failed to subscribe to events: %v", err)
	}

	evtSub.winAPIHandle = windows.Handle(handle)
	return nil
}

func (evtSub *EventSubscription) Close() error {
	if evtSub.winAPIHandle == 0 {
		return fmt.Errorf("windows_events: no active subscription to close")
	}
	ret, _, err := procEvtClose.Call(uintptr(evtSub.winAPIHandle))
	if ret == 0 {
		return fmt.Errorf("windows_events: error closing handle: %s", err)
	}
	evtSub.winAPIHandle = 0
	return nil
}

func (evtSub *EventSubscription) winAPICallback(action, userContext, event uintptr) uintptr {
	switch action {
	case evtSubscribeActionError:
		evtSub.Errors <- fmt.Errorf("windows_events: error in callback, code: %x", uint16(event))
	case evtSubscribeActionDeliver:
		bufferSize := uint32(4096)
		for {
			renderSpace := make([]uint16, bufferSize/2)
			bufferUsed := uint32(0)
			propertyCount := uint32(0)
			ret, _, err := procEvtRender.Call(
				0,
				event,
				evtRenderEventXML,
				uintptr(bufferSize),
				uintptr(unsafe.Pointer(&renderSpace[0])),
				uintptr(unsafe.Pointer(&bufferUsed)),
				uintptr(unsafe.Pointer(&propertyCount)),
			)
			if ret == 0 {
				if err == windows.ERROR_INSUFFICIENT_BUFFER {
					bufferSize *= 2
					continue
				}
				evtSub.Errors <- fmt.Errorf("windows_events: failed to render event: %w", err)
				return 0
			}

			xmlStr := windows.UTF16ToString(renderSpace)
			xmlStr = cleanXML(xmlStr)

			dataParsed := new(Event)
			if err := xml.Unmarshal([]byte(xmlStr), dataParsed); err != nil {
				evtSub.Errors <- fmt.Errorf("windows_events: failed to parse XML: %s", err)
			} else {
				evtSub.Callback(dataParsed)
			}
			break
		}
	default:
		evtSub.Errors <- fmt.Errorf("windows_events: unsupported action in callback: %x", uint16(action))
	}
	return 0
}

func cleanXML(xml string) string {
	xml = strings.TrimSpace(xml)

	if idx := strings.Index(xml, "<?xml"); idx > 0 {
		xml = xml[idx:]
	}

	xml = strings.Map(func(r rune) rune {
		if r < 32 && r != '\n' && r != '\r' && r != '\t' {
			return -1
		}
		return r
	}, xml)

	return xml
}

var (
	exitChan   = make(chan os.Signal, 1)
	errorsChan = make(chan error, 10)
)

func main() {
	signal.Notify(exitChan, os.Interrupt)

	channels := []string{"Security", "Application", "System"}
	subscriptions := make([]*EventSubscription, 0)

	for _, channel := range channels {
		sub := &EventSubscription{
			Channel: channel,
			Query:   "*",
			Errors:  errorsChan,
			Callback: func(e *Event) {
				eventCallback(e)
			},
		}

		if err := sub.Create(); err != nil {
			log.Printf("Error subscribing to channel %s: %s", channel, err)
			continue
		}

		subscriptions = append(subscriptions, sub)
		log.Printf("Subscribed to channel: %s", channel)
	}

	go func() {
		for err := range errorsChan {
			log.Printf("Subscription error: %s", err)
		}
	}()

	<-exitChan
	log.Println("Interrupt received, closing subscriptions...")
	for _, sub := range subscriptions {
		if err := sub.Close(); err != nil {
			log.Printf("Error closing subscription for %s: %v", sub.Channel, err)
		}
	}
	log.Println("Agent finished successfully.")
}

func eventCallback(event *Event) {
	eventJSON := EventJSON{
		ProviderName:  event.System.Provider.ProviderName,
		ProviderGUID:  event.System.Provider.ProviderGUID,
		EventID:       event.System.EventID,
		Version:       event.System.Version,
		Level:         event.System.Level,
		Task:          event.System.Task,
		Opcode:        event.System.Opcode,
		Keywords:      event.System.Keywords,
		TimeCreated:   event.System.TimeCreated.SystemTime,
		Timestamp:     event.System.TimeCreated.SystemTime,
		EventRecordID: event.System.EventRecordID,
		Correlation:   event.System.Correlation,
		Execution:     event.System.Execution,
		Channel:       event.System.Channel,
		Computer:      event.System.Computer,
		EventData:     make(map[string]interface{}),
	}

	for _, data := range event.EventData {
		if strings.HasPrefix(data.Value, "0x") {
			if val, err := strconv.ParseInt(data.Value[2:], 16, 64); err == nil {
				eventJSON.EventData[data.Key] = val
				continue
			}
		}

		if data.Key != "" {
			value := strings.TrimSpace(data.Value)
			if value != "" {
				eventJSON.EventData[data.Key] = value
			}
		}
	}

	jsonData, err := json.MarshalIndent(eventJSON, "", "    ")
	if err != nil {
		log.Printf("Error converting event to JSON: %s", err)
		return
	}

	fmt.Println(string(jsonData))
}
