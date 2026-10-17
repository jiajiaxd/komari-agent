package loginmon

import (
	"fmt"
	"testing"
	"time"
)

func TestParseSSHDMessage(t *testing.T) {
	at := time.Date(2026, 10, 17, 8, 0, 0, 0, time.UTC)
	cases := []struct {
		msg        string
		ok         bool
		user, ip   string
		port       int
		authMethod string
	}{
		{"Accepted publickey for root from 203.0.113.5 port 52314 ssh2: ED25519 SHA256:abc", true, "root", "203.0.113.5", 52314, "publickey"},
		{"Oct 17 08:00:00 host sshd-session[1234]: Accepted password for alice from 2001:db8::1 port 2222 ssh2", true, "alice", "2001:db8::1", 2222, "password"},
		{"Accepted keyboard-interactive/pam for bob from ::ffff:198.51.100.7 port 1 ssh2", true, "bob", "198.51.100.7", 1, "keyboard-interactive/pam"},
		{"Failed password for root from 203.0.113.5 port 52314 ssh2", false, "", "", 0, ""},
		{"Accepted password for root from not-an-ip port 22 ssh2", false, "", "", 0, ""},
	}
	for _, c := range cases {
		ev, ok := parseSSHDMessage(c.msg, at)
		if ok != c.ok {
			t.Fatalf("%q: ok=%v, want %v", c.msg, ok, c.ok)
		}
		if !ok {
			continue
		}
		if ev.Protocol != "ssh" || ev.Username != c.user || ev.SourceIP != c.ip || ev.SourcePort != c.port || ev.AuthMethod != c.authMethod || !ev.Time.Equal(at) {
			t.Fatalf("%q: got %+v", c.msg, ev)
		}
	}
}

const rdpEventXML = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID><TimeCreated SystemTime='2026-10-17T08:01:02.1234567Z'/><EventRecordID>98765</EventRecordID><Channel>Security</Channel></System><EventData><Data Name='TargetUserName'>Administrator</Data><Data Name='TargetDomainName'>WIN-HOST</Data><Data Name='LogonType'>%s</Data><Data Name='AuthenticationPackageName'>Negotiate</Data><Data Name='IpAddress'>%s</Data><Data Name='IpPort'>50123</Data></EventData></Event>`

func TestRDPLogon(t *testing.T) {
	cases := []struct {
		logonType, ip string
		ok            bool
	}{
		{"10", "203.0.113.9", true},
		{"7", "203.0.113.9", true},
		{"7", "127.0.0.1", false},
		{"3", "203.0.113.9", false},
		{"10", "-", false},
	}
	for _, c := range cases {
		ev, err := parseWinEvent([]byte(fmt.Sprintf(rdpEventXML, c.logonType, c.ip)))
		if err != nil {
			t.Fatal(err)
		}
		if ev.System.EventRecordID != 98765 {
			t.Fatalf("record id = %d", ev.System.EventRecordID)
		}
		login, ok := ev.rdpLogon()
		if ok != c.ok {
			t.Fatalf("type %s ip %s: ok=%v", c.logonType, c.ip, ok)
		}
		if ok && (login.Protocol != "rdp" || login.Username != `WIN-HOST\Administrator` || login.SourceIP != c.ip || login.SourcePort != 50123 ||
			!login.Time.Equal(time.Date(2026, 10, 17, 8, 1, 2, 123456700, time.UTC))) {
			t.Fatalf("got %+v", login)
		}
	}
}

func TestWindowsOpenSSHLogon(t *testing.T) {
	xml := `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>4</EventID><TimeCreated SystemTime='2026-10-17T08:01:02Z'/><EventRecordID>12</EventRecordID></System><EventData><Data Name='process'>sshd.exe</Data><Data Name='payload'>Accepted password for user1 from 198.51.100.3 port 61000 ssh2</Data></EventData></Event>`
	ev, err := parseWinEvent([]byte(xml))
	if err != nil {
		t.Fatal(err)
	}
	login, ok := ev.sshLogon()
	if !ok || login.Username != "user1" || login.SourceIP != "198.51.100.3" {
		t.Fatalf("got %+v ok=%v", login, ok)
	}
}
