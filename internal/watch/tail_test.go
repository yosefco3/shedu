package watch

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func next(t *testing.T, ch <-chan string) string {
	t.Helper()
	select {
	case s, ok := <-ch:
		if !ok {
			t.Fatal("channel closed")
		}
		return s
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for line")
	}
	return ""
}

func TestTailLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(path, []byte("old line\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := TailLines(ctx, path, 20*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("first\nsecond\npart")
	f.Sync()
	if got := next(t, ch); got != "first" {
		t.Errorf("got %q", got)
	}
	if got := next(t, ch); got != "second" {
		t.Errorf("got %q", got)
	}
	select {
	case s := <-ch:
		t.Fatalf("partial line must not be emitted, got %q", s)
	case <-time.After(100 * time.Millisecond):
	}
	f.WriteString("ial\n")
	f.Close()
	if got := next(t, ch); got != "partial" {
		t.Errorf("got %q", got)
	}

	// rotation: rename the old file, create a new one
	os.Rename(path, path+".1")
	os.WriteFile(path, []byte("after rotate\n"), 0o644)
	if got := next(t, ch); got != "after rotate" {
		t.Errorf("after rotation got %q", got)
	}

	// truncation
	os.WriteFile(path, []byte("x\n"), 0o644)
	if got := next(t, ch); got != "x" {
		t.Errorf("after truncate got %q", got)
	}
	cancel()
	for range ch {
	}
}
