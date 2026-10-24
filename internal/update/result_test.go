package update

import (
	"os"
	"testing"
	"time"
)

func TestResultHandoff(t *testing.T) {
	dir := t.TempDir()
	if _, ok := TakeResult(dir); ok {
		t.Fatal("no file yet")
	}
	want := RunResult{From: "v0.3.0", Version: "v0.3.1", OK: true, At: time.Date(2026, 10, 25, 3, 47, 0, 0, time.UTC)}
	if err := WriteResult(dir, want); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(ResultFile(dir)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode: %v %v", fi, err)
	}
	got, ok := TakeResult(dir)
	if !ok || got != want {
		t.Fatalf("got %+v %v", got, ok)
	}
	if _, ok := TakeResult(dir); ok {
		t.Error("taking it removes it")
	}
	os.WriteFile(ResultFile(dir), []byte("{broken"), 0o600) //nolint:errcheck
	if _, ok := TakeResult(dir); ok {
		t.Error("a broken file is not a result")
	}
	if _, err := os.Stat(ResultFile(dir)); !os.IsNotExist(err) {
		t.Error("a broken file is removed")
	}
}

func TestRecentFailure(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Date(2026, 10, 25, 3, 47, 0, 0, time.UTC)
	if _, ok := RecentFailure(dir, "v0.3.1", t0); ok {
		t.Fatal("nothing recorded yet")
	}
	if err := RecordFailure(dir, "v0.3.1", t0); err != nil {
		t.Fatal(err)
	}
	if at, ok := RecentFailure(dir, "v0.3.1", t0.Add(time.Hour)); !ok || !at.Equal(t0) {
		t.Error("an hour later the same version is skipped")
	}
	if _, ok := RecentFailure(dir, "v0.3.2", t0.Add(time.Hour)); ok {
		t.Error("a newer version is tried at once")
	}
	if _, ok := RecentFailure(dir, "v0.3.1", t0.Add(RetryAfter)); ok {
		t.Error("the next night it is tried again")
	}
	ClearFailure(dir)
	if _, ok := RecentFailure(dir, "v0.3.1", t0.Add(time.Hour)); ok {
		t.Error("cleared")
	}
}
