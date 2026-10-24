package update

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// RunResult is what `shedu upgrade --auto` leaves in Dir/result.json for the daemon, which
// turns it into an agent.updated or agent.update_failed event. A file is the handoff
// because the daemon is restarted in the middle of a successful upgrade.
type RunResult struct {
	From       string    `json:"from"`              // version running before
	Version    string    `json:"version,omitempty"` // version tried
	OK         bool      `json:"ok"`
	UpToDate   bool      `json:"up_to_date,omitempty"` // nothing to do
	Skipped    bool      `json:"skipped,omitempty"`    // this version failed recently; tried again later
	RolledBack bool      `json:"rolled_back,omitempty"`
	Reason     string    `json:"reason,omitempty"` // why it failed, in English
	At         time.Time `json:"at"`
}

// ResultFile is the result's path in dir.
func ResultFile(dir string) string { return filepath.Join(or(dir, DefaultDir), "result.json") }

// WriteResult stores r atomically (mode 0600).
func WriteResult(dir string, r RunResult) error {
	path := ResultFile(dir)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// TakeResult reads and removes the result, if there is one. A broken file is removed
// and reported as not there.
func TakeResult(dir string) (RunResult, bool) {
	path := ResultFile(dir)
	b, err := os.ReadFile(path)
	if err != nil {
		return RunResult{}, false
	}
	os.Remove(path) //nolint:errcheck
	var r RunResult
	if json.Unmarshal(b, &r) != nil {
		return RunResult{}, false
	}
	return r, true
}

// RetryAfter is how long a version that failed is left alone. It stops a rollback (which
// restarts the service) from starting the same failing update again right away.
const RetryAfter = 20 * time.Hour

type failure struct {
	Version string    `json:"version"`
	At      time.Time `json:"at"`
}

func failureFile(dir string) string { return filepath.Join(or(dir, DefaultDir), "last_failure.json") }

// RecordFailure notes that version v failed at t; ClearFailure forgets it.
func RecordFailure(dir, v string, t time.Time) error {
	b, _ := json.Marshal(failure{v, t})
	if err := os.MkdirAll(or(dir, DefaultDir), 0o700); err != nil {
		return err
	}
	return os.WriteFile(failureFile(dir), b, 0o600)
}

func ClearFailure(dir string) { os.Remove(failureFile(dir)) } //nolint:errcheck

// RecentFailure reports when v last failed, if that was less than RetryAfter before now.
func RecentFailure(dir, v string, now time.Time) (time.Time, bool) {
	b, err := os.ReadFile(failureFile(dir))
	if err != nil {
		return time.Time{}, false
	}
	var f failure
	if json.Unmarshal(b, &f) != nil || f.Version != v || now.Sub(f.At) >= RetryAfter {
		return time.Time{}, false
	}
	return f.At, true
}
