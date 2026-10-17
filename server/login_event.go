package server

import (
	"time"

	v2 "github.com/komari-monitor/komari-agent/protocol/v2"
)

// PostLoginEvents uploads a batch of observed remote logins to the panel.
func PostLoginEvents(events []v2.LoginEvent) error {
	return postV2RPC(v2.Request{
		JSONRPC: v2.Version,
		Method:  v2.MethodAgentLoginEvent,
		Params:  v2.LoginEventParams{Events: events},
		ID:      time.Now().UnixNano(),
	})
}
