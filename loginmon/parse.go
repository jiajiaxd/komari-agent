package loginmon

import (
	"encoding/xml"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	v2 "github.com/komari-monitor/komari-agent/protocol/v2"
)

var sshdAcceptedRe = regexp.MustCompile(`Accepted (\S+) for (\S+) from (\S+) port (\d+)`)

// parseSSHDMessage extracts a successful login from an sshd log message, e.g.
// "Accepted publickey for root from 203.0.113.5 port 52314 ssh2: ED25519 SHA256:...".
func parseSSHDMessage(msg string, at time.Time) (v2.LoginEvent, bool) {
	m := sshdAcceptedRe.FindStringSubmatch(msg)
	if m == nil {
		return v2.LoginEvent{}, false
	}
	ip := normalizeIP(m[3])
	if ip == "" {
		return v2.LoginEvent{}, false
	}
	port, _ := strconv.Atoi(m[4])
	return v2.LoginEvent{
		Protocol:   "ssh",
		Username:   m[2],
		SourceIP:   ip,
		SourcePort: port,
		AuthMethod: m[1],
		Time:       at.UTC(),
	}, true
}

func normalizeIP(s string) string {
	s = strings.Trim(strings.TrimSpace(s), "[]")
	if i := strings.IndexByte(s, '%'); i >= 0 {
		s = s[:i]
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// winEvent is the subset of a rendered Windows event XML that we need.
type winEvent struct {
	System struct {
		EventID       int    `xml:"EventID"`
		EventRecordID uint64 `xml:"EventRecordID"`
		TimeCreated   struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

func parseWinEvent(data []byte) (*winEvent, error) {
	var ev winEvent
	if err := xml.Unmarshal(data, &ev); err != nil {
		return nil, err
	}
	return &ev, nil
}

func (e *winEvent) field(name string) string {
	for _, d := range e.EventData.Data {
		if d.Name == name {
			return strings.TrimSpace(d.Value)
		}
	}
	return ""
}

func (e *winEvent) time() time.Time {
	if t, err := time.Parse(time.RFC3339Nano, e.System.TimeCreated.SystemTime); err == nil {
		return t.UTC()
	}
	return time.Now().UTC()
}

// rdpLogon converts a Security 4624 event into an RDP login. Logon type 10 is
// RemoteInteractive; type 7 (unlock) is only counted when it comes from a remote
// address, which is how Windows records reconnecting to a disconnected RDP session.
func (e *winEvent) rdpLogon() (v2.LoginEvent, bool) {
	if e.System.EventID != 4624 {
		return v2.LoginEvent{}, false
	}
	ip := normalizeIP(e.field("IpAddress"))
	if ip == "" {
		return v2.LoginEvent{}, false
	}
	switch e.field("LogonType") {
	case "10":
	case "7":
		if net.ParseIP(ip).IsLoopback() {
			return v2.LoginEvent{}, false
		}
	default:
		return v2.LoginEvent{}, false
	}
	user := e.field("TargetUserName")
	if domain := e.field("TargetDomainName"); domain != "" && domain != "-" {
		user = domain + `\` + user
	}
	port, _ := strconv.Atoi(e.field("IpPort"))
	return v2.LoginEvent{
		Protocol:   "rdp",
		Username:   user,
		SourceIP:   ip,
		SourcePort: port,
		AuthMethod: e.field("AuthenticationPackageName"),
		Time:       e.time(),
	}, true
}

// sshLogon handles events from the Windows OpenSSH server, which writes the
// usual sshd text into one of the event data fields.
func (e *winEvent) sshLogon() (v2.LoginEvent, bool) {
	for _, d := range e.EventData.Data {
		if ev, ok := parseSSHDMessage(d.Value, e.time()); ok {
			return ev, true
		}
	}
	return v2.LoginEvent{}, false
}
