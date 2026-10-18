package watch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

// ScanPreloadFile returns the active lines of /etc/ld.so.preload (fsys is
// the host's /). Most servers have no such file; "" means none or empty.
func ScanPreloadFile(fsys fs.FS) string {
	b, err := fs.ReadFile(fsys, "etc/ld.so.preload")
	if err != nil {
		return ""
	}
	var lines []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			lines = append(lines, l)
		}
	}
	return strings.Join(lines, " ")
}

// LDPreload extracts the LD_PRELOAD value from a NUL-separated environ.
func LDPreload(environ []byte) string {
	for _, kv := range bytes.Split(environ, []byte{0}) {
		if v, ok := bytes.CutPrefix(kv, []byte("LD_PRELOAD=")); ok {
			return string(v)
		}
	}
	return ""
}

// SuspiciousPreload reports an LD_PRELOAD that loads anything outside the
// package-managed folders. fakeroot (package builds) is always fine.
func SuspiciousPreload(val string) bool {
	for _, lib := range strings.FieldsFunc(val, func(r rune) bool { return r == ':' || r == ' ' }) {
		if strings.Contains(lib, "libfakeroot") {
			continue
		}
		if !hasAnyPrefix(lib, systemDirs) {
			return true
		}
	}
	return false
}

// PreloadedProcs returns pid → LD_PRELOAD for processes with a suspicious one.
// Reading another user's environ needs root; unreadable ones are skipped.
func PreloadedProcs(root fs.FS, procs []Process) map[int]string {
	out := map[int]string{}
	for _, p := range procs {
		b, err := fs.ReadFile(root, path.Join(strconv.Itoa(p.PID), "environ"))
		if err != nil {
			continue
		}
		if v := LDPreload(b); v != "" && SuspiciousPreload(v) {
			out[p.PID] = v
		}
	}
	return out
}

// PreloadFix shows the injected libraries and who owns them.
const PreloadFix = "sudo cat /etc/ld.so.preload; sudo ls -l $(sudo cat /etc/ld.so.preload)"

type preloadState struct {
	Hash string `json:"hash"`
}

const preloadStateFile = "preload.json"

// PreloadWatcher reports when /etc/ld.so.preload appears or changes. Unlike
// other watchers it has no silent baseline: the file is rare enough that one
// already present on the first run is worth one alert.
type PreloadWatcher struct {
	FS       fs.FS // the host's /
	Interval time.Duration
	StateDir string
	Clock    func() time.Time

	st *preloadState
}

// NewPreloadWatcher returns the production watcher.
func NewPreloadWatcher(stateDir string) *PreloadWatcher {
	return &PreloadWatcher{FS: os.DirFS("/"), Interval: time.Minute, StateDir: stateDir, Clock: time.Now}
}

// Run polls until ctx ends.
func (w *PreloadWatcher) Run(ctx context.Context, _ *State, out chan<- Event, _ func() error) {
	runTicker(ctx, w.Interval, out, w.Tick)
}

// Tick checks the file once.
func (w *PreloadWatcher) Tick() []Event {
	if w.st == nil {
		w.st = &preloadState{}
		loadSide(w.StateDir, preloadStateFile, w.st)
	}
	content := ScanPreloadFile(w.FS)
	hash := ""
	if content != "" {
		sum := sha256.Sum256([]byte(content))
		hash = hex.EncodeToString(sum[:])
	}
	if hash == w.st.Hash {
		return nil
	}
	prev := w.st.Hash
	w.st.Hash = hash
	_ = saveSide(w.StateDir, preloadStateFile, w.st)
	if content == "" {
		return nil // removed: nothing to warn about
	}
	now := time.Now()
	if w.Clock != nil {
		now = w.Clock()
	}
	args := map[string]string{"source": "file", "content": shorten(content, 300)}
	if prev != "" {
		args["changed"] = "1"
	}
	return []Event{{Kind: PreloadChanged, Detail: content, Time: now, Args: args}}
}
