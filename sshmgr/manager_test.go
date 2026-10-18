//go:build !windows

package sshmgr

import (
	"reflect"
	"testing"

	v2 "github.com/komari-monitor/komari-agent/protocol/v2"
)

func TestListenHosts(t *testing.T) {
	s := parseEffectiveConfig("listenaddress [::]:22\nlistenaddress 0.0.0.0:22\nlistenaddress 10.0.0.5:22\n")
	if hosts := listenHosts(s); !reflect.DeepEqual(hosts, []string{"::1", "127.0.0.1", "10.0.0.5"}) {
		t.Fatalf("hosts %v", hosts)
	}
	if hosts := listenHosts(nil); !reflect.DeepEqual(hosts, []string{"127.0.0.1"}) {
		t.Fatalf("default hosts %v", hosts)
	}
}

func TestDesiredConfig(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		p     plan
		prl   string
		pa    bool
		ports []int
		want  map[string]string
	}{
		{plan{port: 22}, "yes", true, []int{22}, map[string]string{}},
		{plan{port: 2222}, "yes", true, []int{22, 2222}, map[string]string{"Port": "2222"}},
		{plan{rootLogin: &yes}, "prohibit-password", false, []int{22}, map[string]string{"PermitRootLogin": "yes", "PasswordAuthentication": "yes"}},
		{plan{rootLogin: &no}, "yes", true, []int{22}, map[string]string{"PermitRootLogin": "prohibit-password"}},
		{plan{rootLogin: &no}, "no", true, []int{22}, map[string]string{}},
	}
	for i, c := range cases {
		got := desiredConfig(c.p, &v2.SSHState{PermitRootLogin: c.prl, PasswordAuthentication: c.pa, Ports: c.ports})
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("case %d: got %v want %v", i, got, c.want)
		}
	}
}
