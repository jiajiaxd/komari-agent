//go:build windows

package loginmon

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"
	"unsafe"

	v2 "github.com/komari-monitor/komari-agent/protocol/v2"
	"golang.org/x/sys/windows"
)

var (
	wevtapi       = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtQuery  = wevtapi.NewProc("EvtQuery")
	procEvtNext   = wevtapi.NewProc("EvtNext")
	procEvtRender = wevtapi.NewProc("EvtRender")
	procEvtClose  = wevtapi.NewProc("EvtClose")
)

const (
	evtQueryChannelPath      = 0x1
	evtQueryForwardDirection = 0x100
	evtQueryReverseDirection = 0x200
	evtRenderEventXML        = 1
	evtInfinite              = 0xFFFFFFFF

	errorEvtChannelNotFound = windows.Errno(15007)

	pollInterval = 5 * time.Second
)

type eventSource struct {
	channel string
	// filter is an XPath predicate on System, combined with the EventRecordID cursor.
	filter string
	// dataFilter optionally narrows events by EventData.
	dataFilter string
	convert    func(*winEvent) (v2.LoginEvent, bool)

	lastID   uint64
	disabled bool
}

func (s *eventSource) query() string {
	q := fmt.Sprintf("*[System[(EventRecordID>%d)%s]]", s.lastID, s.filter)
	if s.dataFilter != "" {
		q += " and " + s.dataFilter
	}
	return q
}

func watch(ctx context.Context, emit func(v2.LoginEvent)) {
	if err := wevtapi.Load(); err != nil {
		log.Printf("login monitor: wevtapi.dll unavailable, login monitoring disabled: %v", err)
		return
	}
	sources := []*eventSource{
		{
			channel:    "Security",
			filter:     " and (EventID=4624)",
			dataFilter: "*[EventData[Data[@Name='LogonType']='10' or Data[@Name='LogonType']='7']]",
			convert:    (*winEvent).rdpLogon,
		},
		{
			channel: "OpenSSH/Operational",
			convert: (*winEvent).sshLogon,
		},
	}
	active := 0
	for _, s := range sources {
		id, err := latestRecordID(s.channel)
		if err != nil {
			s.disabled = true
			if !errors.Is(err, errorEvtChannelNotFound) {
				log.Printf("login monitor: cannot read event log %s: %v", s.channel, err)
			}
			continue
		}
		s.lastID = id
		active++
		log.Printf("login monitor: watching event log %s", s.channel)
	}
	if active == 0 {
		log.Println("login monitor: no readable event log, login monitoring disabled")
		return
	}

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		for _, s := range sources {
			if !s.disabled {
				pollSource(s, emit)
			}
		}
	}
}

func pollSource(s *eventSource, emit func(v2.LoginEvent)) {
	// The log was cleared: record IDs start over.
	if latest, err := latestRecordID(s.channel); err == nil && latest < s.lastID {
		s.lastID = latest
	}
	err := forEachEvent(s.channel, s.query(), evtQueryForwardDirection, 0, func(ev *winEvent) bool {
		if ev.System.EventRecordID > s.lastID {
			s.lastID = ev.System.EventRecordID
		}
		if login, ok := s.convert(ev); ok {
			emit(login)
		}
		return true
	})
	if err != nil {
		log.Printf("login monitor: failed to query event log %s: %v", s.channel, err)
	}
}

func latestRecordID(channel string) (uint64, error) {
	var id uint64
	err := forEachEvent(channel, "*", evtQueryReverseDirection, 1, func(ev *winEvent) bool {
		id = ev.System.EventRecordID
		return false
	})
	return id, err
}

// forEachEvent runs an event log query and calls fn for each rendered event
// until fn returns false, limit events were seen (0 = no limit) or the result set ends.
func forEachEvent(channel, query string, direction uint32, limit int, fn func(*winEvent) bool) error {
	channelPtr, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return err
	}
	queryPtr, err := windows.UTF16PtrFromString(query)
	if err != nil {
		return err
	}
	h, _, callErr := procEvtQuery.Call(0, uintptr(unsafe.Pointer(channelPtr)), uintptr(unsafe.Pointer(queryPtr)), uintptr(evtQueryChannelPath|direction))
	if h == 0 {
		return callErr
	}
	defer procEvtClose.Call(h)

	seen := 0
	handles := make([]uintptr, 16)
	for {
		var returned uint32
		r, _, callErr := procEvtNext.Call(h, uintptr(len(handles)), uintptr(unsafe.Pointer(&handles[0])), evtInfinite, 0, uintptr(unsafe.Pointer(&returned)))
		if r == 0 {
			if errors.Is(callErr, windows.ERROR_NO_MORE_ITEMS) {
				return nil
			}
			return callErr
		}
		stop := false
		for _, eh := range handles[:returned] {
			if !stop {
				if data, err := renderEventXML(eh); err == nil {
					if ev, err := parseWinEvent(data); err == nil {
						seen++
						if !fn(ev) || (limit > 0 && seen >= limit) {
							stop = true
						}
					}
				}
			}
			procEvtClose.Call(eh)
		}
		if stop {
			return nil
		}
	}
}

func renderEventXML(event uintptr) ([]byte, error) {
	var used, props uint32
	r, _, err := procEvtRender.Call(0, event, evtRenderEventXML, 0, 0, uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
	if r == 0 && !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		return nil, err
	}
	if used == 0 {
		return nil, errors.New("empty event")
	}
	buf := make([]uint16, (used+1)/2)
	r, _, err = procEvtRender.Call(0, event, evtRenderEventXML, uintptr(len(buf)*2), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
	if r == 0 {
		return nil, err
	}
	return []byte(windows.UTF16ToString(buf)), nil
}
