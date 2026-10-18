package watch

import (
	"context"
	"io/fs"
	"os/user"
	"strconv"
	"strings"
	"time"
)

// Reasons returned by SuspiciousExec; they are also the alert/finding suffixes.
const (
	ReasonTmpExec     = "tmp_exec"
	ReasonDeletedExec = "deleted_exec"
)

// tmpDirs are world-writable places a dropper writes to and runs from.
var tmpDirs = []string{"/tmp/", "/var/tmp/", "/dev/shm/"}

// systemDirs hold package-managed binaries. A deleted binary here is what
// `apt upgrade` leaves behind until the service restarts, not an intruder.
var systemDirs = []string{"/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/", "/snap/"}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// SuspiciousExec returns ReasonTmpExec, ReasonDeletedExec, or "" for a normal
// process. Kernel threads and processes we may not inspect (Exe == "") are normal.
func SuspiciousExec(p Process) string {
	if p.Exe == "" {
		return ""
	}
	if strings.HasPrefix(p.Exe, "/memfd:") {
		// fileless: code loaded straight into memory. runc does this legitimately.
		if strings.HasPrefix(p.Exe, "/memfd:runc") {
			return ""
		}
		return ReasonDeletedExec
	}
	// deleted wins over tmp: hiding the file is the stronger signal
	if p.ExeDeleted && !hasAnyPrefix(p.Exe, systemDirs) {
		return ReasonDeletedExec
	}
	if hasAnyPrefix(p.Exe, tmpDirs) {
		return ReasonTmpExec
	}
	return ""
}

// procKey identifies one process instance: pids are reused, start times are not.
func procKey(p Process) string {
	return strconv.Itoa(p.PID) + ":" + strconv.FormatUint(p.StartTicks, 10)
}

// ProcArgs is the alert/finding detail for a process.
func ProcArgs(p Process, userName func(int) string) map[string]string {
	name := strconv.Itoa(p.UID)
	if userName != nil {
		name = userName(p.UID)
	}
	return map[string]string{
		"pid":  strconv.Itoa(p.PID),
		"exe":  p.Exe,
		"comm": p.Comm,
		"user": name,
		"cmd":  shorten(strings.Join(p.Cmdline, " "), 200),
	}
}

func shorten(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// LookupUser maps a uid to its login name, falling back to the number.
func LookupUser(uid int) string {
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		return u.Username
	}
	return strconv.Itoa(uid)
}

// procState is the watcher's private memory: which (process, reason) pairs
// were already reported, so one process never alerts twice.
type procState struct {
	Reported map[string]time.Time `json:"reported"` // "pid:start:reason" → when
}

const procStateFile = "proc.json"

// ProcWatcher snapshots /proc every Interval and reports processes that look
// like droppers. Later rules (lineage, miner, preload) hang off the same tick.
type ProcWatcher struct {
	Root     fs.FS // /proc; needs ReadLink support for exe/cwd
	Interval time.Duration
	StateDir string
	UserName func(uid int) string
	Clock    func() time.Time

	st *procState
}

// NewProcWatcher returns the production watcher.
func NewProcWatcher(stateDir string) *ProcWatcher {
	return &ProcWatcher{Root: newProcFS("/proc"), Interval: 30 * time.Second, StateDir: stateDir, UserName: LookupUser, Clock: time.Now}
}

// Run polls until ctx ends.
func (w *ProcWatcher) Run(ctx context.Context, _ *State, out chan<- Event, _ func() error) {
	runTicker(ctx, w.Interval, out, w.Tick)
}

// Tick takes one snapshot and returns the new events.
func (w *ProcWatcher) Tick() []Event {
	if w.st == nil {
		w.st = &procState{}
		loadSide(w.StateDir, procStateFile, w.st)
		if w.st.Reported == nil {
			w.st.Reported = map[string]time.Time{}
		}
	}
	now := time.Now()
	if w.Clock != nil {
		now = w.Clock()
	}
	procs, err := Inventory(w.Root)
	if err != nil {
		return nil
	}
	var evs []Event
	alive := map[string]bool{}
	report := func(p Process, reason string, kind Kind, extra map[string]string) {
		key := procKey(p) + ":" + reason
		alive[key] = true
		if _, done := w.st.Reported[key]; done {
			return
		}
		w.st.Reported[key] = now
		args := ProcArgs(p, w.UserName)
		args["reason"] = reason
		for k, v := range extra {
			args[k] = v
		}
		evs = append(evs, Event{Kind: kind, User: args["user"], Detail: p.Exe, Time: now, Args: args})
	}
	for _, p := range procs {
		if reason := SuspiciousExec(p); reason != "" {
			report(p, reason, ProcSuspicious, nil)
		}
	}
	changed := len(evs) > 0
	for key := range w.st.Reported { // forget processes that are gone
		if !alive[key] {
			delete(w.st.Reported, key)
			changed = true
		}
	}
	if changed {
		_ = saveSide(w.StateDir, procStateFile, w.st)
	}
	return evs
}
