//go:build linux

package loginmon

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	v2 "github.com/komari-monitor/komari-agent/protocol/v2"
)

// sshd 写日志的 syslog 标识；OpenSSH 9.8+ 由 sshd-session 记录认证结果
var sshdIdentifiers = []string{"sshd", "sshd-session"}

var authLogFiles = []string{"/var/log/auth.log", "/var/log/secure", "/var/log/messages"}

func watch(ctx context.Context, emit func(v2.LoginEvent)) {
	if journaldAvailable() {
		log.Println("login monitor: watching sshd logins via journald")
		watchJournal(ctx, emit)
		return
	}
	for _, path := range authLogFiles {
		if f, err := os.Open(path); err == nil {
			f.Close()
			log.Printf("login monitor: watching sshd logins via %s", path)
			watchAuthLog(ctx, path, emit)
			return
		}
	}
	log.Println("login monitor: no readable journald or auth log found, SSH login monitoring disabled")
}

func journaldAvailable() bool {
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return false
	}
	_, err := exec.LookPath("journalctl")
	return err == nil
}

func watchJournal(ctx context.Context, emit func(v2.LoginEvent)) {
	var cursor string
	backoff := 5 * time.Second
	for ctx.Err() == nil {
		started := time.Now()
		next, err := followJournal(ctx, cursor, emit)
		if next != "" {
			cursor = next
		}
		if ctx.Err() != nil {
			return
		}
		if time.Since(started) > time.Minute {
			backoff = 5 * time.Second
		}
		log.Printf("login monitor: journalctl exited (%v), restarting in %s", err, backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 5*time.Minute)
	}
}

type journalEntry struct {
	Message  json.RawMessage `json:"MESSAGE"`
	Realtime string          `json:"__REALTIME_TIMESTAMP"`
	Cursor   string          `json:"__CURSOR"`
}

// followJournal runs journalctl until it exits and returns the last cursor seen.
func followJournal(ctx context.Context, cursor string, emit func(v2.LoginEvent)) (string, error) {
	args := []string{"--follow", "--output=json", "--no-pager", "--quiet"}
	if cursor != "" {
		args = append(args, "--after-cursor="+cursor)
	} else {
		args = append(args, "--lines=0")
	}
	for _, id := range sshdIdentifiers {
		args = append(args, "SYSLOG_IDENTIFIER="+id)
	}
	cmd := exec.CommandContext(ctx, "journalctl", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", err
	}
	go logJournalStderr(stderr)

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		var entry journalEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}
		if entry.Cursor != "" {
			cursor = entry.Cursor
		}
		if ev, ok := parseSSHDMessage(journalMessage(entry.Message), journalTime(entry.Realtime)); ok {
			emit(ev)
		}
	}
	return cursor, cmd.Wait()
}

func logJournalStderr(r io.Reader) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" {
			log.Printf("login monitor: journalctl: %s", line)
		}
	}
}

// journalMessage decodes MESSAGE, which journald emits as a byte array when it
// is not valid UTF-8.
func journalMessage(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var b []byte
	var ints []int
	if err := json.Unmarshal(raw, &ints); err == nil {
		b = make([]byte, len(ints))
		for i, v := range ints {
			b[i] = byte(v)
		}
	}
	return string(b)
}

func journalTime(us string) time.Time {
	if v, err := strconv.ParseInt(us, 10, 64); err == nil && v > 0 {
		return time.UnixMicro(v)
	}
	return time.Now()
}

func watchAuthLog(ctx context.Context, path string, emit func(v2.LoginEvent)) {
	for ctx.Err() == nil {
		err := tailFile(ctx, path, time.Second, func(line string) {
			if !isSSHDLine(line) {
				return
			}
			// syslog 时间戳没有年份和时区，按读取时间记录（轮询间隔 1 秒）
			if ev, ok := parseSSHDMessage(line, time.Now()); ok {
				emit(ev)
			}
		})
		if ctx.Err() != nil {
			return
		}
		log.Printf("login monitor: failed to follow %s: %v, retrying in 30s", path, err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
	}
}

func isSSHDLine(line string) bool {
	for _, id := range sshdIdentifiers {
		if strings.Contains(line, " "+id+"[") || strings.Contains(line, " "+id+":") {
			return true
		}
	}
	return false
}
