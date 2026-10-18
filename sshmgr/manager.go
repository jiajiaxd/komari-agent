//go:build !windows

// Package sshmgr reads and edits root's SSH login settings on behalf of the
// panel: authorized_keys, the sshd port and whether root may log in with a
// password. Every apply restarts sshd and verifies the result on disk and on
// the running daemon; config edits are rolled back when sshd stops answering.
package sshmgr

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	v2 "github.com/komari-monitor/komari-agent/protocol/v2"
)

var (
	sshdConfigPath = "/etc/ssh/sshd_config"
	applyMu        sync.Mutex
)

const rootUser = "root"

type account struct {
	home     string
	uid, gid int
}

func rootAccount() account {
	acc := account{home: "/root"}
	if u, err := user.Lookup(rootUser); err == nil {
		if u.HomeDir != "" {
			acc.home = u.HomeDir
		}
		acc.uid, _ = strconv.Atoi(u.Uid)
		acc.gid, _ = strconv.Atoi(u.Gid)
	}
	return acc
}

func authorizedKeysPath(acc account) string {
	return filepath.Join(acc.home, ".ssh", "authorized_keys")
}

func findSSHD() string {
	if p, err := exec.LookPath("sshd"); err == nil {
		return p
	}
	for _, p := range []string{"/usr/sbin/sshd", "/usr/local/sbin/sshd", "/usr/bin/sshd", "/sbin/sshd"} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

// runSSHD runs sshd in test mode. Debian-based systems refuse to test the
// configuration while the privilege separation directory is missing, which is
// common with socket activation, so create it and retry once.
func runSSHD(ctx context.Context, sshd string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, sshd, args...).CombinedOutput()
	if err != nil && strings.Contains(string(out), "privilege separation directory") {
		for _, dir := range []string{"/run/sshd", "/var/run/sshd"} {
			if strings.Contains(string(out), dir) {
				_ = os.MkdirAll(dir, 0o755)
			}
		}
		out, err = exec.CommandContext(ctx, sshd, args...).CombinedOutput()
	}
	return strings.TrimSpace(string(out)), err
}

// effectiveSettings asks sshd for its effective global configuration and
// falls back to evaluating the files directly.
func effectiveSettings(ctx context.Context) (map[string][]string, error) {
	if sshd := findSSHD(); sshd != "" {
		tctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		out, err := runSSHD(tctx, sshd, "-T", "-f", sshdConfigPath)
		cancel()
		if err == nil {
			return parseEffectiveConfig(out), nil
		}
		log.Printf("sshd -T failed, evaluating %s directly: %s", sshdConfigPath, firstLine(out))
	}
	tree, err := loadConfigTree(sshdConfigPath)
	if err != nil {
		return nil, err
	}
	return tree.staticSettings(), nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func readState(ctx context.Context) (*v2.SSHState, map[string][]string, error) {
	acc := rootAccount()
	state := &v2.SSHState{
		User:               rootUser,
		AuthorizedKeysPath: authorizedKeysPath(acc),
		ConfigPath:         sshdConfigPath,
		Keys:               []v2.SSHAuthorizedKey{},
	}
	data, err := os.ReadFile(state.AuthorizedKeysPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("read %s: %w", state.AuthorizedKeysPath, err)
	}
	state.Keys = ParseAuthorizedKeys(string(data))

	settings, err := effectiveSettings(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("read sshd configuration: %w", err)
	}
	state.Ports = parsePorts(settings["port"])
	if v := settings["permitrootlogin"]; len(v) > 0 {
		state.PermitRootLogin = strings.ToLower(v[0])
	}
	if v := settings["passwordauthentication"]; len(v) > 0 {
		state.PasswordAuthentication = strings.EqualFold(v[0], "yes")
	}
	state.RootPasswordLogin = state.PermitRootLogin == "yes" && state.PasswordAuthentication
	state.Service = detectService(ctx)
	return state, settings, nil
}

func requireRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("the agent must run as root to manage SSH settings")
	}
	return nil
}

// Get reports the current SSH settings.
func Get(ctx context.Context) v2.SSHResult {
	applyMu.Lock()
	defer applyMu.Unlock()
	if err := requireRoot(); err != nil {
		return v2.SSHResult{Error: err.Error()}
	}
	state, _, err := readState(ctx)
	if err != nil {
		return v2.SSHResult{Error: err.Error()}
	}
	return v2.SSHResult{OK: true, State: state}
}

type plan struct {
	add       []v2.SSHAuthorizedKey
	remove    []string
	port      int
	rootLogin *bool
}

func validate(ch *v2.SSHChanges) (plan, error) {
	var p plan
	if ch == nil {
		return p, errors.New("no changes requested")
	}
	for _, line := range ch.AddKeys {
		if strings.TrimSpace(line) == "" {
			continue
		}
		k, err := ParseKeyLine(line)
		if err != nil {
			return p, fmt.Errorf("invalid public key: %v", err)
		}
		k.Options = ""
		p.add = append(p.add, k)
	}
	for _, fp := range ch.RemoveKeys {
		fp = strings.TrimSpace(fp)
		if fp == "" {
			continue
		}
		if !strings.HasPrefix(fp, "SHA256:") {
			return p, fmt.Errorf("invalid key fingerprint %q", fp)
		}
		p.remove = append(p.remove, fp)
	}
	if ch.Port < 0 || ch.Port > 65535 {
		return p, fmt.Errorf("invalid port %d", ch.Port)
	}
	p.port = ch.Port
	p.rootLogin = ch.RootPasswordLogin
	if len(p.add) == 0 && len(p.remove) == 0 && p.port == 0 && p.rootLogin == nil {
		return p, errors.New("no changes requested")
	}
	return p, nil
}

// desiredConfig lists the sshd_config directives that differ from the
// current effective configuration.
func desiredConfig(p plan, state *v2.SSHState) map[string]string {
	desired := map[string]string{}
	if p.port > 0 && !slices.Equal(state.Ports, []int{p.port}) {
		desired["Port"] = strconv.Itoa(p.port)
	}
	if p.rootLogin != nil {
		if *p.rootLogin {
			if state.PermitRootLogin != "yes" {
				desired["PermitRootLogin"] = "yes"
			}
			if !state.PasswordAuthentication {
				desired["PasswordAuthentication"] = "yes"
			}
		} else if state.PermitRootLogin == "yes" {
			// Keep key-based root logins working.
			desired["PermitRootLogin"] = "prohibit-password"
		}
	}
	return desired
}

// Apply edits the SSH settings, restarts sshd and verifies the result.
func Apply(ctx context.Context, ch *v2.SSHChanges) (res v2.SSHResult) {
	applyMu.Lock()
	defer applyMu.Unlock()
	defer func() {
		if res.State == nil {
			if state, _, err := readState(ctx); err == nil {
				res.State = state
			}
		}
		res.OK = res.Error == ""
	}()

	if err := requireRoot(); err != nil {
		res.Error = err.Error()
		return
	}
	p, err := validate(ch)
	if err != nil {
		res.Error = err.Error()
		return
	}
	state, _, err := readState(ctx)
	if err != nil {
		res.Error = err.Error()
		return
	}
	acc := rootAccount()

	// authorized_keys
	keysPath := state.AuthorizedKeysPath
	oldKeys, err := os.ReadFile(keysPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		res.Error = fmt.Sprintf("read %s: %v", keysPath, err)
		return
	}
	newKeys, keysChanged := EditAuthorizedKeys(string(oldKeys), p.add, p.remove)

	// sshd_config
	desired := desiredConfig(p, state)
	if port, ok := desired["Port"]; ok {
		n, _ := strconv.Atoi(port)
		if portBusy(n) && !slices.Contains(state.Ports, n) {
			res.Error = fmt.Sprintf("port %d is already in use by another program", n)
			return
		}
	}
	var tree *configTree
	var configEdits map[string]string
	if len(desired) > 0 {
		if tree, err = loadConfigTree(sshdConfigPath); err != nil {
			res.Error = fmt.Sprintf("read %s: %v", sshdConfigPath, err)
			return
		}
		configEdits = editConfig(tree.files, desired)
	}

	if keysChanged {
		if err := writeAuthorizedKeys(keysPath, []byte(newKeys), acc); err != nil {
			res.Error = fmt.Sprintf("write %s: %v", keysPath, err)
			return
		}
	}
	originals := map[string]string{}
	rollback := func() {
		for path, content := range originals {
			if err := writeFilePreserving(path, []byte(content)); err != nil {
				log.Printf("Failed to restore %s: %v", path, err)
			}
		}
	}
	for _, f := range tree.filesOrNil() {
		edited, ok := configEdits[f.Path]
		if !ok {
			continue
		}
		originals[f.Path] = f.Content
		if err := writeFilePreserving(f.Path, []byte(edited)); err != nil {
			rollback()
			res.Error = fmt.Sprintf("write %s: %v", f.Path, err)
			return
		}
	}
	sshd := findSSHD()
	if len(originals) > 0 && sshd != "" {
		tctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		out, err := runSSHD(tctx, sshd, "-t", "-f", sshdConfigPath)
		cancel()
		if err != nil {
			rollback()
			res.Error = "sshd rejected the new configuration, changes were reverted: " + firstLine(out)
			return
		}
	}
	if port, ok := desired["Port"]; ok {
		allowSELinuxPort(ctx, port)
	}

	res.Changed = keysChanged || len(originals) > 0
	var checks []v2.SSHCheck
	if res.Changed {
		service, err := restartSSH(ctx)
		check := v2.SSHCheck{Name: "service_restart", OK: err == nil, Detail: service}
		if err != nil {
			check.Detail = err.Error()
		}
		res.Restarted = err == nil
		checks = append(checks, check)
	}
	checks = append(checks, verify(ctx, p, keysPath, configEdits, &res)...)

	if len(originals) > 0 && (!res.Restarted || failed(checks, "port_listening")) {
		rollback()
		if _, err := restartSSH(ctx); err != nil {
			log.Printf("Failed to restart sshd after rollback: %v", err)
		}
		res.RolledBack = true
		res.State = nil
		res.Checks = checks
		res.Error = "sshd did not come back with the new configuration, configuration changes were reverted"
		return
	}
	res.Checks = checks
	res.Verified = !failed(checks, "")
	if !res.Verified {
		res.Error = "verification failed"
	}
	return
}

func (t *configTree) filesOrNil() []*configFile {
	if t == nil {
		return nil
	}
	return t.files
}

func failed(checks []v2.SSHCheck, name string) bool {
	for _, c := range checks {
		if !c.OK && (name == "" || c.Name == name) {
			return true
		}
	}
	return false
}

// verify re-reads everything from disk and from the running sshd.
func verify(ctx context.Context, p plan, keysPath string, configEdits map[string]string, res *v2.SSHResult) []v2.SSHCheck {
	var checks []v2.SSHCheck
	if len(p.add) > 0 || len(p.remove) > 0 {
		check := v2.SSHCheck{Name: "authorized_keys", OK: true}
		data, err := os.ReadFile(keysPath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			check.OK, check.Detail = false, err.Error()
		} else {
			present := map[string]bool{}
			for _, k := range ParseAuthorizedKeys(string(data)) {
				present[k.Fingerprint] = true
			}
			var problems []string
			for _, k := range p.add {
				if !present[k.Fingerprint] && !slices.Contains(p.remove, k.Fingerprint) {
					problems = append(problems, "missing "+k.Fingerprint)
				}
			}
			for _, fp := range p.remove {
				if present[fp] {
					problems = append(problems, "still present "+fp)
				}
			}
			if len(problems) > 0 {
				check.OK, check.Detail = false, strings.Join(problems, "; ")
			}
		}
		checks = append(checks, check)
	}
	if len(configEdits) > 0 {
		check := v2.SSHCheck{Name: "sshd_config", OK: true}
		for path, want := range configEdits {
			got, err := os.ReadFile(path)
			if err != nil || string(got) != want {
				check.OK, check.Detail = false, path
				break
			}
		}
		checks = append(checks, check)
	}

	state, settings, err := readState(ctx)
	if err != nil {
		return append(checks, v2.SSHCheck{Name: "effective_config", OK: false, Detail: err.Error()})
	}
	res.State = state
	if p.port > 0 || p.rootLogin != nil {
		check := v2.SSHCheck{Name: "effective_config", OK: true}
		var problems []string
		if p.port > 0 && !slices.Equal(state.Ports, []int{p.port}) {
			problems = append(problems, fmt.Sprintf("port is %v", state.Ports))
		}
		if p.rootLogin != nil && state.RootPasswordLogin != *p.rootLogin {
			problems = append(problems, fmt.Sprintf("PermitRootLogin %s, PasswordAuthentication %v", state.PermitRootLogin, state.PasswordAuthentication))
		}
		if len(problems) > 0 {
			check.OK, check.Detail = false, strings.Join(problems, "; ")
		}
		checks = append(checks, check)
	}
	if res.Restarted {
		ports := state.Ports
		if p.port > 0 {
			ports = []int{p.port}
		}
		checks = append(checks, probeSSH(ctx, listenHosts(settings), ports))
	}
	return checks
}

// listenHosts maps sshd listen addresses to loopback addresses to probe.
func listenHosts(settings map[string][]string) []string {
	var hosts []string
	add := func(h string) {
		if !slices.Contains(hosts, h) {
			hosts = append(hosts, h)
		}
	}
	for _, addr := range settings["listenaddress"] {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = strings.Trim(addr, "[]")
		}
		switch host {
		case "0.0.0.0", "":
			add("127.0.0.1")
		case "::":
			add("::1")
		default:
			add(host)
		}
	}
	if len(hosts) == 0 {
		add("127.0.0.1")
	}
	return hosts
}

// probeSSH waits until sshd answers with its banner on every port.
func probeSSH(ctx context.Context, hosts []string, ports []int) v2.SSHCheck {
	check := v2.SSHCheck{Name: "port_listening"}
	deadline := time.Now().Add(15 * time.Second)
	var missing []string
	for {
		missing = missing[:0]
		for _, port := range ports {
			ok := false
			for _, host := range hosts {
				if sshBanner(ctx, net.JoinHostPort(host, strconv.Itoa(port))) {
					ok = true
					break
				}
			}
			if !ok {
				missing = append(missing, strconv.Itoa(port))
			}
		}
		if len(missing) == 0 || time.Now().After(deadline) || ctx.Err() != nil {
			break
		}
		time.Sleep(time.Second)
	}
	check.OK = len(missing) == 0
	if check.OK {
		check.Detail = "listening on " + joinInts(ports)
	} else {
		check.Detail = "no SSH banner on port " + strings.Join(missing, ", ")
	}
	return check
}

func sshBanner(ctx context.Context, addr string) bool {
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4)
	n, _ := conn.Read(buf)
	return string(buf[:n]) == "SSH-"
}

func portBusy(port int) bool {
	l, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return true
	}
	l.Close()
	return false
}

func joinInts(v []int) string {
	s := make([]string, len(v))
	for i, n := range v {
		s[i] = strconv.Itoa(n)
	}
	return strings.Join(s, ", ")
}
