//go:build windows

package sshmgr

import (
	"context"

	v2 "github.com/komari-monitor/komari-agent/protocol/v2"
)

const errUnsupported = "SSH management is not supported on Windows"

func Get(context.Context) v2.SSHResult {
	return v2.SSHResult{Error: errUnsupported}
}

func Apply(context.Context, *v2.SSHChanges) v2.SSHResult {
	return v2.SSHResult{Error: errUnsupported}
}
