//go:build !windows

package sshmgr

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type serviceKind int

const (
	serviceNone serviceKind = iota
	serviceSystemd
	serviceSystemdSocket
	serviceOpenRC
	serviceInitScript
	serviceBSD
	serviceLaunchd
	serviceSignal
)

type sshService struct {
	kind    serviceKind
	name    string // unit, service or script name
	service string // systemd service unit behind a socket unit
}

func (s sshService) String() string {
	switch s.kind {
	case serviceSystemd, serviceSystemdSocket:
		return s.name
	case serviceOpenRC:
		return "rc-service " + s.name
	case serviceInitScript:
		return "/etc/init.d/" + s.name
	case serviceBSD:
		return "service " + s.name
	case serviceLaunchd:
		return "launchd " + s.name
	case serviceSignal:
		return "SIGHUP"
	}
	return ""
}

func run(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func systemctlShow(ctx context.Context, unit, prop string) string {
	out, err := run(ctx, "systemctl", "show", "-p", prop, "--value", unit)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

func hasSystemd() bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	st, err := os.Stat("/run/systemd/system")
	return err == nil && st.IsDir()
}

func findService(ctx context.Context) sshService {
	if hasSystemd() {
		service := ""
		for _, unit := range []string{"ssh.service", "sshd.service"} {
			if systemctlShow(ctx, unit, "LoadState") == "loaded" {
				service = systemctlShow(ctx, unit, "Id")
				if service == "" {
					service = unit
				}
				break
			}
		}
		// Ubuntu 22.10+ starts sshd through ssh.socket, which owns the ports.
		for _, unit := range []string{"ssh.socket", "sshd.socket"} {
			if systemctlShow(ctx, unit, "ActiveState") == "active" {
				return sshService{kind: serviceSystemdSocket, name: unit, service: service}
			}
		}
		if service != "" {
			return sshService{kind: serviceSystemd, name: service}
		}
	}
	switch runtime.GOOS {
	case "darwin":
		return sshService{kind: serviceLaunchd, name: "system/com.openssh.sshd"}
	case "freebsd", "openbsd", "netbsd", "dragonfly":
		return sshService{kind: serviceBSD, name: "sshd"}
	}
	if _, err := exec.LookPath("rc-service"); err == nil {
		for _, name := range []string{"sshd", "ssh"} {
			if _, err := os.Stat("/etc/init.d/" + name); err == nil {
				return sshService{kind: serviceOpenRC, name: name}
			}
		}
	}
	for _, name := range []string{"ssh", "sshd"} {
		if st, err := os.Stat("/etc/init.d/" + name); err == nil && st.Mode()&0o111 != 0 {
			return sshService{kind: serviceInitScript, name: name}
		}
	}
	if sshdPID() > 0 {
		return sshService{kind: serviceSignal}
	}
	return sshService{kind: serviceNone}
}

func detectService(ctx context.Context) string {
	return findService(ctx).String()
}

func sshdPID() int {
	for _, path := range []string{"/run/sshd.pid", "/var/run/sshd.pid"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && pid > 1 {
			return pid
		}
	}
	return 0
}

// restartSSH restarts sshd so that the new configuration and port take
// effect. Running SSH sessions survive a restart of the listener.
func restartSSH(ctx context.Context) (string, error) {
	svc := findService(ctx)
	var out string
	var err error
	switch svc.kind {
	case serviceSystemdSocket:
		// The socket generator derives the listening ports from sshd_config.
		if out, err = run(ctx, "systemctl", "daemon-reload"); err == nil {
			out, err = run(ctx, "systemctl", "restart", svc.name)
		}
		if err == nil && svc.service != "" && systemctlShow(ctx, svc.service, "ActiveState") == "active" {
			out, err = run(ctx, "systemctl", "restart", svc.service)
		}
	case serviceSystemd:
		out, err = run(ctx, "systemctl", "restart", svc.name)
	case serviceOpenRC:
		out, err = run(ctx, "rc-service", svc.name, "restart")
	case serviceInitScript:
		out, err = run(ctx, "/etc/init.d/"+svc.name, "restart")
	case serviceBSD:
		out, err = run(ctx, "service", svc.name, "restart")
	case serviceLaunchd:
		out, err = run(ctx, "launchctl", "kickstart", "-k", svc.name)
	case serviceSignal:
		// sshd re-executes itself and rereads its configuration on SIGHUP.
		err = syscall.Kill(sshdPID(), syscall.SIGHUP)
	default:
		return "", errors.New("no SSH service found")
	}
	if err != nil {
		if out != "" {
			return svc.String(), fmt.Errorf("restart %s: %v: %s", svc, err, firstLine(out))
		}
		return svc.String(), fmt.Errorf("restart %s: %v", svc, err)
	}
	return svc.String(), nil
}

// allowSELinuxPort labels a new port for sshd when SELinux is enforcing;
// sshd cannot bind an unlabeled port there.
func allowSELinuxPort(ctx context.Context, port string) {
	if _, err := exec.LookPath("semanage"); err != nil {
		return
	}
	if out, err := run(ctx, "getenforce"); err != nil || !strings.EqualFold(out, "enforcing") {
		return
	}
	if _, err := run(ctx, "semanage", "port", "-a", "-t", "ssh_port_t", "-p", "tcp", port); err != nil {
		_, _ = run(ctx, "semanage", "port", "-m", "-t", "ssh_port_t", "-p", "tcp", port)
	}
}
