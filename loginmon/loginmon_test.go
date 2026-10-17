package loginmon

import (
	"context"
	"sync"
	"testing"
	"time"

	v2 "github.com/komari-monitor/komari-agent/protocol/v2"
	"github.com/komari-monitor/komari-agent/server"
)

func TestSenderBatchesAndStopsOnUnsupportedPanel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	calls := 0
	sent := 0
	go runSender(ctx, func(evs []v2.LoginEvent) error {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls == 1 {
			sent += len(evs)
			return nil
		}
		return &server.RPCCallError{Code: -32601, Message: "method not found"}
	})

	for i := 0; i < 3; i++ {
		emit(v2.LoginEvent{Protocol: "ssh", Username: "root", SourceIP: "203.0.113.1"})
	}
	time.Sleep(flushInterval + 500*time.Millisecond)
	emit(v2.LoginEvent{Protocol: "ssh", Username: "root", SourceIP: "203.0.113.2"})
	time.Sleep(flushInterval + 500*time.Millisecond)
	emit(v2.LoginEvent{Protocol: "ssh", Username: "root", SourceIP: "203.0.113.3"})
	time.Sleep(flushInterval + 500*time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if sent != 3 {
		t.Fatalf("first batch sent %d events, want 3", sent)
	}
	if calls != 2 {
		t.Fatalf("send called %d times, want 2 (paused after method-not-found)", calls)
	}
}
