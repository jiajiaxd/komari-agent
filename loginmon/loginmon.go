// Package loginmon passively watches the host's authentication logs for
// successful SSH/RDP logins and reports them to the panel. It never hooks into
// the login path itself, so a slow or unreachable panel cannot delay a login.
package loginmon

import (
	"context"
	"errors"
	"log"
	"time"

	v2 "github.com/komari-monitor/komari-agent/protocol/v2"
	"github.com/komari-monitor/komari-agent/server"
)

// Sender uploads a batch of login events.
type Sender func([]v2.LoginEvent) error

const (
	queueSize     = 256
	batchSize     = 20
	maxPending    = 200
	flushInterval = 2 * time.Second
	minBackoff    = 5 * time.Second
	maxBackoff    = 5 * time.Minute
	// 旧版面板不认识 agent.loginEvent 时暂停上报的时长
	unsupportedPause = time.Hour
)

var queue = make(chan v2.LoginEvent, queueSize)

// emit enqueues an event without ever blocking the watcher.
func emit(ev v2.LoginEvent) {
	select {
	case queue <- ev:
	default:
		log.Printf("login monitor: queue full, dropping %s login of %s from %s", ev.Protocol, ev.Username, ev.SourceIP)
	}
}

// Start runs the platform watcher and the uploader until ctx is done.
func Start(ctx context.Context, send Sender) {
	go runSender(ctx, send)
	watch(ctx, emit)
}

func runSender(ctx context.Context, send Sender) {
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	var pending []v2.LoginEvent
	var backoff time.Duration
	var nextTry time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-queue:
			pending = append(pending, ev)
			if len(pending) > maxPending {
				pending = append([]v2.LoginEvent(nil), pending[len(pending)-maxPending:]...)
			}
			if len(pending) < batchSize {
				continue
			}
		case <-ticker.C:
		}
		if len(pending) == 0 || time.Now().Before(nextTry) {
			continue
		}

		batch := pending
		if len(batch) > batchSize {
			batch = batch[:batchSize]
		}
		err := send(batch)
		if err == nil {
			pending = append([]v2.LoginEvent(nil), pending[len(batch):]...)
			backoff = 0
			continue
		}
		var rpcErr *server.RPCCallError
		if errors.As(err, &rpcErr) && rpcErr.Code == -32601 {
			log.Printf("login monitor: panel does not support login events, pausing uploads for %s", unsupportedPause)
			pending = nil
			nextTry = time.Now().Add(unsupportedPause)
			continue
		}
		backoff = min(max(backoff*2, minBackoff), maxBackoff)
		nextTry = time.Now().Add(backoff)
		log.Printf("login monitor: failed to upload %d login event(s), retrying in %s: %v", len(batch), backoff, err)
	}
}
