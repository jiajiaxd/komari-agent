package server

import (
	"context"
	"log"
	"time"

	v2 "github.com/komari-monitor/komari-agent/protocol/v2"
	"github.com/komari-monitor/komari-agent/sshmgr"
)

// handleSSHRequest reads or edits the SSH settings and returns the result
// through the authenticated POST transport.
func handleSSHRequest(params v2.SSHRequestParams) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var result v2.SSHResult
	switch params.Action {
	case v2.SSHActionGet:
		result = sshmgr.Get(ctx)
	case v2.SSHActionApply:
		if flags.DisableWebSsh {
			result = v2.SSHResult{Error: "remote control is disabled on this agent"}
		} else {
			result = sshmgr.Apply(ctx, params.Changes)
		}
	default:
		result = v2.SSHResult{Error: "unknown SSH action " + params.Action}
	}
	result.RequestID = params.RequestID
	if params.Action == v2.SSHActionApply {
		log.Printf("SSH settings apply finished: ok=%v changed=%v restarted=%v verified=%v rolled_back=%v %s",
			result.OK, result.Changed, result.Restarted, result.Verified, result.RolledBack, result.Error)
	}
	postCtx, postCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer postCancel()
	payload := v2.NewRequest(params.RequestID, v2.MethodAgentSSHResult, result)
	if _, err := postV2RequestContext(postCtx, payload); err != nil {
		// Transport errors may contain the token, never log them.
		log.Print("Failed to return SSH management result")
	}
}
