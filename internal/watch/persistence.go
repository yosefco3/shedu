package watch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

// PersistItem is one place where something can start itself: a crontab, a
// cron script, or a systemd unit.
type PersistItem struct {
	Source string `json:"source"` // "cron" or "systemd"
	Path   string `json:"path"`   // absolute path on the host
	Hash   string `json:"hash"`
	Body   string `json:"body,omitempty"` // kept for small text files so changes can be shown
}

const maxPersistBody = 4096

// persistence locations, relative to /. Globs are expanded one level; the
// systemd trees are walked (units, drop-ins and *.wants symlinks).
var (
	cronGlobs = []string{
		"etc/crontab", "etc/cron.d/*", "etc/cron.hourly/*", "etc/cron.daily/*",
		"etc/cron.weekly/*", "etc/cron.monthly/*", "var/spool/cron/crontabs/*", "var/spool/cron/*",
		"etc/rc.local",
	}
	systemdTrees = []string{"etc/systemd/system", "root/.config/systemd/user", "home/*/.config/systemd/user"}
)

// ScanPersistence lists every persistence item under fsys (the host's /).
// Unreadable entries are skipped, so a non-root run is partial, not an error.
func ScanPersistence(fsys fs.FS) ([]PersistItem, error) {
	seen := map[string]bool{}
	var items []PersistItem
	add := func(source, name string) {
		if seen[name] {
			return
		}
		st, err := fs.Stat(fsys, name)
		if err != nil || !st.Mode().IsRegular() {
			return
		}
		b, err := fs.ReadFile(fsys, name)
		if err != nil {
			return
		}
		seen[name] = true
		sum := sha256.Sum256(b)
		it := PersistItem{Source: source, Path: "/" + name, Hash: hex.EncodeToString(sum[:])}
		if len(b) <= maxPersistBody {
			it.Body = string(b)
		}
		items = append(items, it)
	}
	for _, g := range cronGlobs {
		names, _ := fs.Glob(fsys, g)
		for _, n := range names {
			if path.Base(n) == ".placeholder" {
				continue // Debian ships these empty markers
			}
			add("cron", n)
		}
	}
	for _, g := range systemdTrees {
		roots, _ := fs.Glob(fsys, g)
		for _, root := range roots {
			_ = fs.WalkDir(fsys, root, func(name string, d fs.DirEntry, err error) error {
				if err != nil {
					return nil
				}
				if strings.Count(strings.TrimPrefix(name, root), "/") > 2 {
					return fs.SkipDir
				}
				if !d.IsDir() {
					add("systemd", name)
				}
				return nil
			})
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Path < items[j].Path })
	return items, nil
}

// PersistFix is the command that shows what the item runs.
func PersistFix(it PersistItem) string {
	if user, ok := strings.CutPrefix(it.Path, "/var/spool/cron/crontabs/"); ok {
		return "sudo crontab -l -u " + user
	}
	if it.Source == "systemd" && strings.HasPrefix(it.Path, "/etc/systemd/system/") {
		return "systemctl cat " + path.Base(it.Path)
	}
	return "sudo cat " + it.Path
}

// isUserLevel reports locations that packages never write to: a new entry
// there was put by a person (or an intruder).
func isUserLevel(p string) bool {
	return strings.HasPrefix(p, "/var/spool/cron/") || strings.Contains(p, "/.config/systemd/user")
}

type persistState struct {
	Taken time.Time              `json:"taken"`
	Items map[string]PersistItem `json:"items"` // path → item
}

const persistStateFile = "persistence.json"

// PersistenceWatcher snapshots cron and systemd every Interval. The first
// snapshot is a silent baseline; afterwards new and changed items are events.
type PersistenceWatcher struct {
	FS       fs.FS // the host's /
	Interval time.Duration
	StateDir string
	Clock    func() time.Time

	st *persistState
}

// NewPersistenceWatcher returns the production watcher.
func NewPersistenceWatcher(stateDir string) *PersistenceWatcher {
	return &PersistenceWatcher{FS: os.DirFS("/"), Interval: time.Minute, StateDir: stateDir, Clock: time.Now}
}

// Run polls until ctx ends.
func (w *PersistenceWatcher) Run(ctx context.Context, _ *State, out chan<- Event, _ func() error) {
	runTicker(ctx, w.Interval, out, w.Tick)
}

// Tick scans once and returns events for new or changed items.
func (w *PersistenceWatcher) Tick() []Event {
	now := time.Now()
	if w.Clock != nil {
		now = w.Clock()
	}
	if w.st == nil {
		w.st = &persistState{}
		loadSide(w.StateDir, persistStateFile, w.st)
	}
	items, err := ScanPersistence(w.FS)
	if err != nil {
		return nil
	}
	cur := make(map[string]PersistItem, len(items))
	for _, it := range items {
		cur[it.Path] = it
	}
	if w.st.Taken.IsZero() {
		w.st.Taken, w.st.Items = now, cur
		_ = saveSide(w.StateDir, persistStateFile, w.st)
		return nil
	}
	var evs []Event
	for _, it := range items {
		old, known := w.st.Items[it.Path]
		if known && old.Hash == it.Hash {
			continue
		}
		args := map[string]string{"source": it.Source, "path": it.Path, "fix": PersistFix(it)}
		if known {
			args["changed"] = "1"
		}
		if isUserLevel(it.Path) {
			args["user_level"] = "1"
		}
		args["diff"] = SimpleDiff(old.Body, it.Body, 10)
		evs = append(evs, Event{Kind: PersistenceNew, Detail: it.Path, Time: now, Args: args})
	}
	removed := len(cur) != len(w.st.Items)
	if len(evs) > 0 || removed {
		w.st.Items = cur
		_ = saveSide(w.StateDir, persistStateFile, w.st)
	}
	return evs
}
