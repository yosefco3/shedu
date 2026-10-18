package watch

import (
	"context"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/yosefco3/shedu/internal/config"
)

// webRoots are the folders whose content an intruder defaces or encrypts.
var webRoots = []string{"var/www", "srv/www", "srv/http", "usr/share/nginx/html"}

const (
	massFileMaxFiles = 50_000 // stop counting here: a huge tree must not cost real CPU
	massFileMaxDepth = 8
)

// CountRecentChanges counts regular files under dir (relative to fsys)
// modified at or after since. It returns at most 3 sample paths. The walk is
// capped by depth and file count, so it is cheap even on a big site.
func CountRecentChanges(fsys fs.FS, dir string, since time.Time) (count int, sample []string) {
	seen := 0
	_ = fs.WalkDir(fsys, dir, func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if strings.Count(strings.TrimPrefix(name, dir), "/") >= massFileMaxDepth {
				return fs.SkipDir
			}
			return nil
		}
		if seen++; seen > massFileMaxFiles {
			return fs.SkipAll
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.ModTime().Before(since) {
			return nil
		}
		count++
		if len(sample) < 3 {
			sample = append(sample, "/"+name)
		}
		return nil
	})
	return count, sample
}

// MassFileWatcher counts recently modified files in each web root every
// MASSFILE_WINDOW and reports a folder where more than MASSFILE_COUNT changed.
type MassFileWatcher struct {
	FS    fs.FS // the host's /
	Dirs  []string
	T     config.Thresholds
	Clock func() time.Time
}

// NewMassFileWatcher watches the web roots that exist on this host.
func NewMassFileWatcher(t config.Thresholds) *MassFileWatcher {
	root := os.DirFS("/")
	var dirs []string
	for _, d := range webRoots {
		if st, err := fs.Stat(root, d); err == nil && st.IsDir() {
			dirs = append(dirs, d)
		}
	}
	return &MassFileWatcher{FS: root, Dirs: dirs, T: t, Clock: time.Now}
}

// Run polls until ctx ends. Without web roots there is nothing to do.
func (w *MassFileWatcher) Run(ctx context.Context, _ *State, out chan<- Event, _ func() error) {
	if len(w.Dirs) == 0 {
		return
	}
	runTicker(ctx, w.window(), out, w.Tick)
}

func (w *MassFileWatcher) window() time.Duration {
	if w.T.MassFileWindow <= 0 {
		return config.ThresholdsFor(config.Normal).MassFileWindow
	}
	return w.T.MassFileWindow
}

// Tick counts changes in the last window for every folder.
func (w *MassFileWatcher) Tick() []Event {
	now := time.Now()
	if w.Clock != nil {
		now = w.Clock()
	}
	limit := w.T.MassFileCount
	if limit <= 0 {
		limit = config.ThresholdsFor(config.Normal).MassFileCount
	}
	var evs []Event
	for _, d := range w.Dirs {
		n, sample := CountRecentChanges(w.FS, d, now.Add(-w.window()))
		if n < limit {
			continue
		}
		evs = append(evs, Event{Kind: MassFileChange, Detail: "/" + d, Time: now, Args: map[string]string{
			"dir": "/" + d, "count": strconv.Itoa(n), "seconds": strconv.Itoa(int(w.window().Seconds())),
			"sample": strings.Join(sample, ", "),
		}})
	}
	return evs
}
