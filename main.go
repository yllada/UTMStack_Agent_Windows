package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/text/encoding/charmap"
)

var (
	modwevtapi    = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtQuery  = modwevtapi.NewProc("EvtQuery")
	procEvtNext   = modwevtapi.NewProc("EvtNext")
	procEvtRender = modwevtapi.NewProc("EvtRender")
	procEvtClose  = modwevtapi.NewProc("EvtClose")
)

const (
	EvtRenderEventXml   = 1
	EvtQueryChannelPath = 0x1
)

func EvtQuery(session windows.Handle, path string, query string, flags uint32) (windows.Handle, error) {
	pPath, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, fmt.Errorf("error converting path: %w", err)
	}
	pQuery, err := windows.UTF16PtrFromString(query)
	if err != nil {
		return 0, fmt.Errorf("error converting query: %w", err)
	}
	ret, _, err := procEvtQuery.Call(
		uintptr(session),
		uintptr(unsafe.Pointer(pPath)),
		uintptr(unsafe.Pointer(pQuery)),
		uintptr(flags),
	)
	if ret == 0 {
		return 0, fmt.Errorf("EvtQuery failed: %w", err)
	}
	return windows.Handle(ret), nil
}

func EvtNext(queryHandle windows.Handle, batchSize uint32) ([]windows.Handle, error) {
	handles := make([]windows.Handle, batchSize)
	var returned uint32
	ret, _, _ := procEvtNext.Call(
		uintptr(queryHandle),
		uintptr(batchSize),
		uintptr(unsafe.Pointer(&handles[0])),
		0,
		0,
		uintptr(unsafe.Pointer(&returned)),
	)
	if ret == 0 {
		return nil, nil
	}
	return handles[:returned], nil
}

func EvtRenderXML(eventHandle windows.Handle) (string, error) {
	var bufferUsed, propertyCount uint32

	ret, _, err := procEvtRender.Call(
		0,
		uintptr(eventHandle),
		uintptr(EvtRenderEventXml),
		0,
		0,
		uintptr(unsafe.Pointer(&bufferUsed)),
		uintptr(unsafe.Pointer(&propertyCount)),
	)
	if ret == 0 && err != windows.ERROR_INSUFFICIENT_BUFFER {
		return "", fmt.Errorf("EvtRender (initial) failed: %w", err)
	}

	buf := make([]byte, bufferUsed)
	ret, _, err = procEvtRender.Call(
		0,
		uintptr(eventHandle),
		uintptr(EvtRenderEventXml),
		uintptr(bufferUsed),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufferUsed)),
		uintptr(unsafe.Pointer(&propertyCount)),
	)
	if ret == 0 {
		return "", fmt.Errorf("EvtRender failed: %w", err)
	}

	u16 := make([]uint16, bufferUsed/2)
	for i := 0; i < int(bufferUsed)/2; i++ {
		u16[i] = uint16(buf[i*2]) | uint16(buf[i*2+1])<<8
	}
	xmlStr := windows.UTF16ToString(u16)
	return xmlStr, nil
}

func EvtClose(handle windows.Handle) error {
	ret, _, err := procEvtClose.Call(uintptr(handle))
	if ret == 0 {
		return fmt.Errorf("EvtClose failed: %w", err)
	}
	return nil
}

type EventXML struct {
	XMLName   xml.Name `xml:"Event"`
	System    System   `xml:"System"`
	EventData *Data    `xml:"EventData"`
}

type System struct {
	Provider      Provider    `xml:"Provider"`
	EventID       EventID     `xml:"EventID"`
	Version       string      `xml:"Version,attr"`
	Level         string      `xml:"Level,attr"`
	Task          string      `xml:"Task,attr"`
	Opcode        string      `xml:"Opcode,attr"`
	Keywords      string      `xml:"Keywords,attr"`
	TimeCreated   Time        `xml:"TimeCreated"`
	EventRecordID string      `xml:"EventRecordID,attr"`
	Correlation   Correlation `xml:"Correlation"`
	Execution     Execution   `xml:"Execution"`
	Channel       string      `xml:"Channel,attr"`
	Computer      string      `xml:"Computer"`
	Security      Security    `xml:"Security"`
}

type Provider struct {
	Name string `xml:"Name,attr"`
	Guid string `xml:"Guid,attr"`
}

type EventID struct {
	Value string `xml:",chardata"`
}

type Time struct {
	SystemTime string `xml:"SystemTime,attr"`
}

type Correlation struct {
	ActivityID        string `xml:"ActivityID,attr"`
	RelatedActivityID string `xml:"RelatedActivityID,attr"`
}

type Execution struct {
	ProcessID string `xml:"ProcessID,attr"`
	ThreadID  string `xml:"ThreadID,attr"`
}

type Security struct {
	UserID string `xml:"UserID,attr"`
}

type Data struct {
	Fields []DataField `xml:"Data"`
}

type DataField struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

type WinlogEvent struct {
	Timestamp string `json:"@timestamp"`
	Message   string `json:"message"`
	Event     struct {
		Code     uint32 `json:"code"`
		Provider string `json:"provider"`
		Kind     string `json:"kind"`
		Created  string `json:"created"`
	} `json:"event"`
	Winlog struct {
		RecordID          uint32            `json:"record_id"`
		Channel           string            `json:"channel"`
		SystemVersion     string            `json:"system_version"`
		ProviderName      string            `json:"provider_name"`
		ProviderGUID      string            `json:"provider_guid"`
		EventID           uint32            `json:"event_id"`
		Level             string            `json:"level"`
		TimeCreated       string            `json:"time_created"`
		ComputerName      string            `json:"computer_name"`
		EventData         map[string]string `json:"event_data"`
		ActivityID        string            `json:"activity_id"`
		RelatedActivityID string            `json:"related_activity_id"`
		Task              string            `json:"task"`
		Opcode            string            `json:"opcode"`
		Keywords          []string          `json:"keywords"`
		ProcessID         string            `json:"process_id"`
		ThreadID          string            `json:"thread_id"`
		UserID            string            `json:"user_id"`
	} `json:"winlog"`
}

func mapEventXML(ev EventXML) WinlogEvent {
	var we WinlogEvent

	we.Timestamp = ev.System.TimeCreated.SystemTime
	we.Event.Created = ev.System.TimeCreated.SystemTime
	we.Event.Provider = ev.System.Provider.Name
	we.Event.Kind = "event"

	code, err := strconv.Atoi(strings.TrimSpace(ev.System.EventID.Value))
	if err == nil {
		we.Event.Code = uint32(code)
		we.Winlog.EventID = uint32(code)
	}

	we.Winlog.ProviderName = ev.System.Provider.Name
	we.Winlog.ProviderGUID = ev.System.Provider.Guid
	we.Winlog.Channel = ev.System.Channel
	we.Winlog.ComputerName = ev.System.Computer
	we.Winlog.Level = ev.System.Level
	we.Winlog.TimeCreated = ev.System.TimeCreated.SystemTime
	we.Winlog.SystemVersion = ev.System.Version
	we.Winlog.Task = ev.System.Task
	we.Winlog.Opcode = ev.System.Opcode

	if recID, err := strconv.Atoi(ev.System.EventRecordID); err == nil {
		we.Winlog.RecordID = uint32(recID)
	}

	we.Winlog.EventData = make(map[string]string)
	if ev.EventData != nil {
		for _, field := range ev.EventData.Fields {
			we.Winlog.EventData[field.Name] = field.Value
		}
	}

	we.Winlog.ActivityID = ev.System.Correlation.ActivityID
	we.Winlog.RelatedActivityID = ev.System.Correlation.RelatedActivityID
	we.Winlog.Keywords = strings.Fields(ev.System.Keywords)
	we.Winlog.ProcessID = ev.System.Execution.ProcessID
	we.Winlog.ThreadID = ev.System.Execution.ThreadID
	we.Winlog.UserID = ev.System.Security.UserID

	return we
}

func processChannel(channel string, query string) error {
	// DEBUG
	log.Printf("Starting processing of channel %s", channel)

	queryHandle, err := EvtQuery(0, channel, query, EvtQueryChannelPath)
	if err != nil {
		return fmt.Errorf("error in EvtQuery for %s: %w", channel, err)
	}
	defer func() {
		if err := EvtClose(queryHandle); err != nil {
			log.Printf("Error closing query %s: %v", channel, err)
		}
	}()

	batchSize := uint32(10)
	for {
		handles, err := EvtNext(queryHandle, batchSize)
		if err != nil {
			log.Printf("Error in EvtNext for %s: %v", channel, err)
			break
		}
		if len(handles) == 0 {
			log.Printf("No more events in %s", channel)
			break
		}
		for _, h := range handles {
			xmlStr, err := EvtRenderXML(h)
			if cerr := EvtClose(h); cerr != nil {
				log.Printf("Error closing event handle in %s: %v", channel, cerr)
			}
			if err != nil {
				log.Printf("Error rendering event in %s: %v", channel, err)
				continue
			}

			var evXML EventXML
			decoder := xml.NewDecoder(bytes.NewBufferString(xmlStr))
			decoder.CharsetReader = charsetReader // para manejar codificaciones (si es necesario)
			if err := decoder.Decode(&evXML); err != nil {
				log.Printf("Error parsing XML in %s: %v", channel, err)
				continue
			}

			we := mapEventXML(evXML)
			we.Event.Provider = evXML.System.Provider.Name
			we.Event.Code = we.Winlog.EventID
			we.Winlog.Channel = channel
			we.Timestamp = evXML.System.TimeCreated.SystemTime
			we.Event.Created = evXML.System.TimeCreated.SystemTime

			jsonBytes, err := json.Marshal(we)
			if err != nil {
				log.Printf("Error converting to JSON in %s: %v", channel, err)
				continue
			}
			fmt.Println(string(jsonBytes))
		}

		time.Sleep(1 * time.Second)
	}

	// DEBUG
	log.Printf("Finished processing channel %s", channel)
	return nil
}

func charsetReader(charset string, input io.Reader) (io.Reader, error) {
	switch charset {
	case "UTF-8":
		return input, nil
	case "ISO-8859-1":
		return charmap.ISO8859_1.NewDecoder().Reader(input), nil
	default:
		return nil, fmt.Errorf("unsupported charset: %s", charset)
	}
}

func main() {
	query := "*[System[TimeCreated[timediff(@SystemTime) <= 300000]]]"

	channels := []string{"Application", "System", "Security"}

	for {
		for _, channel := range channels {
			if err := processChannel(channel, query); err != nil {
				log.Printf("Error processing channel %s: %v", channel, err)
			}
		}
		time.Sleep(1 * time.Minute)
	}
}
