package loginmon

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestTailFileFollowsAppendsAndRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(path, []byte("old line\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var lines []string
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = tailFile(ctx, path, 20*time.Millisecond, func(l string) {
			mu.Lock()
			lines = append(lines, l)
			mu.Unlock()
		})
	}()
	waitFor := func(n int) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			got := len(lines)
			mu.Unlock()
			if got >= n {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		mu.Lock()
		defer mu.Unlock()
		t.Fatalf("timed out waiting for %d lines, got %q", n, lines)
	}

	time.Sleep(50 * time.Millisecond)
	appendTo(t, path, "first\nsec")
	appendTo(t, path, "ond\n")
	waitFor(2)

	// logrotate style: rename, then create a new file.
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	appendTo(t, path+".1", "before-rotate\n")
	appendTo(t, path, "after-rotate\n")
	waitFor(4)

	// copytruncate style.
	time.Sleep(50 * time.Millisecond)
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	appendTo(t, path, "after-truncate\n")
	waitFor(5)

	cancel()
	<-done
	want := []string{"first", "second", "before-rotate", "after-rotate", "after-truncate"}
	mu.Lock()
	defer mu.Unlock()
	if len(lines) != len(want) {
		t.Fatalf("lines = %q, want %q", lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Fatalf("lines = %q, want %q", lines, want)
		}
	}
}

func appendTo(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}
