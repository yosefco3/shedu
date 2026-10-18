package watch

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Detection is one infected file reported by ClamAV.
type Detection struct {
	Path      string
	Signature string
}

// ParseClamOutput reads clamscan/clamdscan output ("path: Sig.Name FOUND").
// The path may itself contain ": ", so the last one splits.
func ParseClamOutput(r io.Reader) []Detection {
	var out []Detection
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		rest, ok := strings.CutSuffix(line, " FOUND")
		if !ok {
			continue
		}
		i := strings.LastIndex(rest, ": ")
		if i <= 0 {
			continue
		}
		out = append(out, Detection{Path: rest[:i], Signature: rest[i+2:]})
	}
	return out
}

// NextAt returns the next "HH:MM" strictly after now, in now's location.
func NextAt(now time.Time, hhmm string) (time.Time, error) {
	t, err := time.Parse("15:04", hhmm)
	if err != nil {
		return time.Time{}, fmt.Errorf("%q: want HH:MM", hhmm)
	}
	next := time.Date(now.Year(), now.Month(), now.Day(), t.Hour(), t.Minute(), 0, 0, now.Location())
	if !next.After(now) {
		next = next.AddDate(0, 0, 1)
	}
	return next, nil
}

// clamTargets are scanned when they exist: where uploads, home files and
// droppers end up. Not the whole disk: a nightly scan must finish.
var clamTargets = []string{"/home", "/root", "/var/www", "/srv", "/opt", "/tmp", "/var/tmp", "/dev/shm"}

// ClamWatcher runs a nightly ClamAV scan at At (CLAMAV_AT) if ClamAV is
// installed. Report-only: it never deletes or moves a file.
type ClamWatcher struct {
	At      string                                                      // "HH:MM"; "" disables
	Targets []string                                                    // folders to scan
	Scan    func(ctx context.Context, targets []string) ([]byte, error) // nil when ClamAV is absent
	Clock   func() time.Time
	Log     func(format string, args ...any)
}

// NewClamWatcher returns the production watcher; Scan is nil without ClamAV.
func NewClamWatcher(at string, logf func(string, ...any)) *ClamWatcher {
	var targets []string
	for _, t := range clamTargets {
		if st, err := os.Stat(t); err == nil && st.IsDir() {
			targets = append(targets, t)
		}
	}
	return &ClamWatcher{At: at, Targets: targets, Scan: clamCommand(), Clock: time.Now, Log: logf}
}

// clamCommand prefers clamdscan (uses the running daemon, fast) and falls
// back to a low-priority clamscan. Exit status 1 means "found", not failure.
func clamCommand() func(context.Context, []string) ([]byte, error) {
	var name string
	var args []string
	if p, err := exec.LookPath("clamdscan"); err == nil {
		name, args = p, []string{"--fdpass", "--multiscan", "--infected", "--no-summary"}
	} else if p, err := exec.LookPath("clamscan"); err == nil {
		name, args = "nice", []string{"-n", "19", p, "-r", "--infected", "--no-summary"}
	} else {
		return nil
	}
	return func(ctx context.Context, targets []string) ([]byte, error) {
		out, err := exec.CommandContext(ctx, name, append(args, targets...)...).Output()
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
			err = nil
		}
		return out, err
	}
}

// Available reports whether there is anything to run.
func (w *ClamWatcher) Available() bool { return w.Scan != nil && w.At != "" && len(w.Targets) > 0 }

func (w *ClamWatcher) now() time.Time {
	if w.Clock != nil {
		return w.Clock()
	}
	return time.Now()
}

// Run waits for At every day and scans. Without ClamAV it returns at once.
func (w *ClamWatcher) Run(ctx context.Context, _ *State, out chan<- Event, _ func() error) {
	if !w.Available() {
		return
	}
	for {
		next, err := NextAt(w.now(), w.At)
		if err != nil {
			w.logf("clamav: %v", err)
			return
		}
		select {
		case <-time.After(next.Sub(w.now())):
		case <-ctx.Done():
			return
		}
		if ev, ok := w.ScanOnce(ctx); ok {
			select {
			case out <- ev:
			case <-ctx.Done():
				return
			}
		}
	}
}

// ScanOnce scans the targets and returns an event when something was found.
func (w *ClamWatcher) ScanOnce(ctx context.Context) (Event, bool) {
	sctx, cancel := context.WithTimeout(ctx, 4*time.Hour)
	defer cancel()
	started := w.now()
	b, err := w.Scan(sctx, w.Targets)
	if err != nil {
		w.logf("clamav: scan failed: %v", err)
		return Event{}, false
	}
	found := ParseClamOutput(bytes.NewReader(b))
	w.logf("clamav: scanned %s in %s, %d infected", strings.Join(w.Targets, " "), w.now().Sub(started).Round(time.Second), len(found))
	if len(found) == 0 {
		return Event{}, false
	}
	var list, paths []string
	for i, d := range found {
		if i == 5 {
			list = append(list, "…")
			break
		}
		list = append(list, d.Path+" ("+d.Signature+")")
		paths = append(paths, "'"+strings.ReplaceAll(d.Path, "'", `'\''`)+"'")
	}
	return Event{Kind: ClamDetected, Time: w.now(), Detail: found[0].Path, Args: map[string]string{
		"count": strconv.Itoa(len(found)), "list": strings.Join(list, "\n"), "paths": strings.Join(paths, " "),
	}}, true
}

func (w *ClamWatcher) logf(format string, args ...any) {
	if w.Log != nil {
		w.Log(format, args...)
	}
}
