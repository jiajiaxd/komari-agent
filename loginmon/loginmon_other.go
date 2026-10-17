//go:build !linux && !windows

package loginmon

import (
	"context"

	v2 "github.com/komari-monitor/komari-agent/protocol/v2"
)

func watch(context.Context, func(v2.LoginEvent)) {}
