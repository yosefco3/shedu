package daemon

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yosefco3/shedu/internal/config"
	"github.com/yosefco3/shedu/internal/finding"
	"github.com/yosefco3/shedu/internal/i18n"
	"github.com/yosefco3/shedu/internal/notify"
	"github.com/yosefco3/shedu/internal/update"
	"github.com/yosefco3/shedu/internal/watch"
	"github.com/yosefco3/shedu/pkg/cloudapi"
)

func TestWindowMinute(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		host := fmt.Sprintf("server-%d.example.com", i)
		m := WindowMinute(host)
		tm, err := time.Parse("15:04", m)
		if err != nil {
			t.Fatalf("WindowMinute(%q) = %q: %v", host, m, err)
		}
		if tm.Hour() < 3 || tm.Hour() > 4 {
			t.Errorf("WindowMinute(%q) = %q, want 03:00-04:59", host, m)
		}
		if WindowMinute(host) != m {
			t.Errorf("WindowMinute(%q) is not stable", host)
		}
		seen[m] = true
	}
	if len(seen) < 10 {
		t.Errorf("20 hosts share only %d distinct minutes: %v", len(seen), seen)
	}
	if WindowMinute("") == "" {
		t.Error("an empty hostname must still get a minute")
	}
}

func TestAutoUpdateTime(t *testing.T) {
	loc := time.FixedZone("IL", 3*3600)
	win := WindowMinute("web-1")
	wt, _ := time.Parse("15:04", win)
	at := func(day, h, m int) time.Time { return time.Date(2026, 10, day, h, m, 0, 0, loc) }

	now := at(17, 1, 0)
	a := &AutoUpdate{At: "now", Host: "web-1"}
	if got := a.Time(now); !got.Equal(now) {
		t.Errorf("now: %v", got)
	}

	a = &AutoUpdate{Host: "web-1"}
	if got, want := a.Time(now), at(17, wt.Hour(), wt.Minute()); !got.Equal(want) {
		t.Errorf("window ahead today: %v, want %v", got, want)
	}
	late := at(17, 23, 0)
	if got, want := a.Time(late), at(18, wt.Hour(), wt.Minute()); !got.Equal(want) {
		t.Errorf("window passed: %v, want %v", got, want)
	}
	if got := a.Time(late); got.Location() != loc {
		t.Errorf("must stay in now's location, got %v", got.Location())
	}

	a = &AutoUpdate{At: "04:15", Host: "web-1"}
	if got, want := a.Time(now), at(17, 4, 15); !got.Equal(want) {
		t.Errorf("04:15 ahead: %v, want %v", got, want)
	}
	if got, want := a.Time(at(17, 4, 15)), at(18, 4, 15); !got.Equal(want) {
		t.Errorf("04:15 exactly now is the next day: %v, want %v", got, want)
	}

	a = &AutoUpdate{At: "tomorrow-ish", Host: "web-1"}
	if got, want := a.Time(now), at(17, wt.Hour(), wt.Minute()); !got.Equal(want) {
		t.Errorf("invalid At must fall back to the window: %v, want %v", got, want)
	}
}

func TestAutoUpdateDescribe(t *testing.T) {
	win := WindowMinute("web-1")
	cases := []struct{ at, want string }{
		{"", win},
		{"now", "now"},
		{"04:15", "04:15"},
	}
	for _, c := range cases {
		got := (&AutoUpdate{At: c.at, Host: "web-1"}).Describe()
		if !strings.Contains(got, c.want) || !strings.Contains(got, "signed releases only") {
			t.Errorf("Describe(%q) = %q, want it to mention %q and signed releases only", c.at, got, c.want)
		}
	}
}

// lockedLog is a log.Logger over a buffer that is safe for the daemon's goroutines.
type lockedLog struct {
	mu sync.Mutex
	sb strings.Builder
}

func (l *lockedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sb.Write(p)
}
func (l *lockedLog) String() string    { l.mu.Lock(); defer l.mu.Unlock(); return l.sb.String() }
func (l *lockedLog) has(s string) bool { return strings.Contains(l.String(), s) }

// latestCloud answers every heartbeat with a fixed LatestVersion.
type latestCloud struct{ latest string }

func (c latestCloud) Heartbeat(context.Context, cloudapi.Heartbeat) (cloudapi.HeartbeatResponse, error) {
	return cloudapi.HeartbeatResponse{LatestVersion: c.latest}, nil
}

// fakeStart records the versions the daemon asked to upgrade to.
type fakeStart struct {
	mu   sync.Mutex
	vers []string
	err  error
}

func (f *fakeStart) start(_ context.Context, v string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.vers = append(f.vers, v)
	return f.err
}

func (f *fakeStart) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.vers...)
}

type autoEnv struct {
	d     *Daemon
	rec   *recorder
	log   *lockedLog
	start *fakeStart
	dir   string
	stop  func()
}

// newAutoEnv builds a quiet daemon (known state: no "connected" message) with the nightly
// update set to "now". cloud may be nil (not enrolled). Run is started; stop cancels it and
// waits for Run to return.
func newAutoEnv(t *testing.T, ver string, cloud Heartbeater) *autoEnv {
	t.Helper()
	e := &autoEnv{rec: &recorder{}, log: &lockedLog{}, start: &fakeStart{}, dir: t.TempDir()}
	e.d = &Daemon{
		Cfg:      config.Config{Lang: i18n.En, Hostname: "web-1"},
		Notifier: e.rec,
		Rules:    watch.NewRules(5),
		State:    &watch.State{KnownIPs: map[string]time.Time{"1.1.1.1": time.Now()}, SudoUsers: map[string]time.Time{}, LastAlerts: map[string]time.Time{}},
		Log:      log.New(e.log, "", 0),
		Version:  ver,
		Cloud:    cloud,
		Addrs:    func() []string { return nil },
		Uptime:   func() int64 { return 1 },
		AutoUpdate: &AutoUpdate{
			At: "now", Host: "web-1", Dir: e.dir, Start: e.start.start,
			Poll: 10 * time.Millisecond, LatestWait: 2 * time.Second,
			Running: func(context.Context) bool { return false }, // never exec systemctl in tests
		},
	}
	return e
}

func (e *autoEnv) run(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.d.Run(ctx) }()
	e.stop = func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Run did not return after cancel")
		}
	}
	t.Cleanup(func() { cancel() })
}

func (e *autoEnv) alerts() []notify.Message {
	e.rec.mu.Lock()
	defer e.rec.mu.Unlock()
	var out []notify.Message
	for _, m := range e.rec.full {
		if m.Alert != nil {
			out = append(out, m)
		}
	}
	return out
}

func TestAutoUpdateEnrolledStartsNewerRelease(t *testing.T) {
	e := newAutoEnv(t, "v0.3.0", latestCloud{"v0.3.1"})
	e.d.HeartbeatEvery = time.Hour
	e.run(t)
	waitFor(t, func() bool { return len(e.start.calls()) == 1 })
	if got := e.start.calls(); got[0] != "v0.3.1" {
		t.Fatalf("Start called with %q, want v0.3.1", got)
	}
	waitFor(t, func() bool { return e.log.has("auto-update: started shedu upgrade --auto (v0.3.1)") })

	// The upgrade (a separate process) leaves its result; the daemon turns it into an alert.
	if err := update.WriteResult(e.dir, update.RunResult{From: "v0.3.0", Version: "v0.3.1", OK: true}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return len(e.alerts()) == 1 })
	m := e.alerts()[0]
	if m.Alert.ID != "agent.updated" || m.Alert.Severity != finding.Info.String() {
		t.Errorf("alert = %+v", m.Alert)
	}
	for _, lang := range []string{"he", "en"} {
		tx := m.Alert.Text[lang]
		if !strings.Contains(tx.Title, "v0.3.1") || !strings.Contains(tx.Explain, "v0.3.1") {
			t.Errorf("%s text lacks the version: %+v", lang, tx)
		}
	}
	if !strings.Contains(m.Text, "v0.3.1") || !strings.Contains(m.Text, "v0.3.0") {
		t.Errorf("telegram text = %q", m.Text)
	}
	if _, err := os.Stat(update.ResultFile(e.dir)); !os.IsNotExist(err) {
		t.Error("the result file must be consumed")
	}
	if got := e.start.calls(); len(got) != 1 {
		t.Errorf("Start called again: %q", got)
	}
	e.stop()
}

func TestAutoUpdateEnrolledUpToDateStartsNothing(t *testing.T) {
	e := newAutoEnv(t, "v0.3.1", latestCloud{"v0.3.1"})
	e.d.HeartbeatEvery = time.Hour
	e.run(t)
	waitFor(t, func() bool { return e.log.has("auto-update: up to date") })
	if got := e.start.calls(); len(got) != 0 {
		t.Errorf("Start called: %q", got)
	}
	e.stop()
}

func TestAutoUpdateNotEnrolledLetsTheUpgradeAskGitHub(t *testing.T) {
	e := newAutoEnv(t, "v0.3.0", nil)
	e.run(t)
	waitFor(t, func() bool { return len(e.start.calls()) == 1 })
	if got := e.start.calls(); got[0] != "" {
		t.Errorf("Start called with %q, want an empty version", got[0])
	}
	waitFor(t, func() bool { return e.log.has("latest from GitHub") })
	e.stop()
}

func TestAutoUpdateSkipsDevBuild(t *testing.T) {
	e := newAutoEnv(t, "dev", nil)
	e.run(t)
	waitFor(t, func() bool { return e.log.has("development build") })
	if got := e.start.calls(); len(got) != 0 {
		t.Errorf("Start called on a dev build: %q", got)
	}
	e.stop()
}

func TestAutoUpdateStartFailureAlerts(t *testing.T) {
	e := newAutoEnv(t, "v0.3.0", nil)
	e.start.err = errors.New("systemd-run not found")
	e.run(t)
	waitFor(t, func() bool { return len(e.alerts()) == 1 })
	a := e.alerts()[0].Alert
	if a.ID != "agent.update_failed" || a.Severity != finding.Medium.String() || a.Fix != "sudo shedu upgrade" {
		t.Errorf("alert = %+v", a)
	}
	if r := a.Args["reason"]; !strings.Contains(r, "could not start") || !strings.Contains(r, "systemd-run not found") {
		t.Errorf("reason = %q", r)
	}
	if !strings.Contains(e.alerts()[0].Text, "could not start") {
		t.Errorf("telegram text lacks the reason: %q", e.alerts()[0].Text)
	}
	if !e.log.has("auto-update: could not start the upgrade") {
		t.Errorf("log:\n%s", e.log.String())
	}
	e.stop()
}

func TestAutoUpdateFailedResultAlertsOncePerCooldown(t *testing.T) {
	e := newAutoEnv(t, "v0.3.0", nil)
	e.d.AutoUpdate.At = "03:00" // no start-up attempt in this test; only the result file matters
	e.d.AutoUpdate.Start = func(context.Context, string) error { t.Error("unexpected start"); return nil }
	e.run(t)

	reason := "the service did not come up after the swap; the previous binary was restored"
	fail := update.RunResult{From: "v0.3.0", Version: "v0.3.1", OK: false, RolledBack: true, Reason: reason}
	if err := update.WriteResult(e.dir, fail); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return len(e.alerts()) == 1 })
	m := e.alerts()[0]
	if m.Alert.ID != "agent.update_failed" || m.Alert.Fix != "sudo shedu upgrade" {
		t.Errorf("alert = %+v", m.Alert)
	}
	for _, lang := range []string{"he", "en"} {
		if tx := m.Alert.Text[lang]; !strings.Contains(tx.Explain, reason) || !strings.Contains(tx.Title, "v0.3.1") {
			t.Errorf("%s text = %+v", lang, tx)
		}
	}
	if !strings.Contains(m.Text, reason) {
		t.Errorf("telegram text = %q", m.Text)
	}

	// A second failure right after is inside the 20h cooldown: consumed, but silent.
	if err := update.WriteResult(e.dir, fail); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { _, err := os.Stat(update.ResultFile(e.dir)); return os.IsNotExist(err) })
	time.Sleep(150 * time.Millisecond)
	if n := len(e.alerts()); n != 1 {
		t.Errorf("second failure inside the cooldown produced %d alerts in total, want 1", n)
	}
	e.stop()
}

func TestAutoUpdateUpToDateResultOnlyLogs(t *testing.T) {
	e := newAutoEnv(t, "v0.3.1", nil)
	e.d.AutoUpdate.At = "03:00"
	e.run(t)
	if err := update.WriteResult(e.dir, update.RunResult{From: "v0.3.1", Version: "v0.3.1", OK: true, UpToDate: true}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return e.log.has("auto-update: up to date (running v0.3.1, latest v0.3.1)") })
	time.Sleep(100 * time.Millisecond)
	if n := len(e.alerts()); n != 0 {
		t.Errorf("an up-to-date result must not alert, got %d", n)
	}
	e.stop()
}

func TestAutoUpdateSkippedResultOnlyLogs(t *testing.T) {
	e := newAutoEnv(t, "v0.3.0", nil)
	e.d.AutoUpdate.At = "03:00"
	e.run(t)
	reason := "v0.3.1 failed recently (2026-10-24 03:00); trying again later"
	if err := update.WriteResult(e.dir, update.RunResult{From: "v0.3.0", Version: "v0.3.1", OK: true, Skipped: true, Reason: reason}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return e.log.has("auto-update: skipped: " + reason) })
	time.Sleep(100 * time.Millisecond)
	if n := len(e.alerts()); n != 0 {
		t.Errorf("a skipped result must not alert, got %d", n)
	}
	e.stop()
}

func TestResultEventEmptyReasonAndMissingVersion(t *testing.T) {
	now := time.Date(2026, 10, 17, 3, 0, 0, 0, time.UTC)
	ev, ok := resultEvent(update.RunResult{From: "v0.3.0"}, now)
	if !ok || ev.Kind != watch.AgentUpdateFailed || ev.Args["reason"] != "unknown error" || ev.Args["version"] != "" {
		t.Errorf("event = %+v, %v", ev, ok)
	}
}

func TestAutoUpdateAlreadyRunningOrNoSystemdOnlyLogs(t *testing.T) {
	for name, tc := range map[string]struct {
		err error
		log string
	}{
		"previous update still running": {ErrUpdateRunning, "an update is already running"},
		"no systemd":                    {fmt.Errorf("%w: not started by systemd", ErrCannotStart), "auto-update: needs systemd"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newAutoEnv(t, "v0.3.0", nil)
			e.start.err = tc.err
			e.run(t)
			waitFor(t, func() bool { return e.log.has(tc.log) })
			time.Sleep(50 * time.Millisecond)
			if n := len(e.alerts()); n != 0 {
				t.Errorf("%d alerts, want none (this is not a failed update)", n)
			}
			e.stop()
		})
	}
}

func TestAutoUpdateWithoutAResultIsReported(t *testing.T) {
	e := newAutoEnv(t, "v0.3.0", nil)
	var running atomic.Bool
	running.Store(true)
	e.d.AutoUpdate.ResultWithin = 30 * time.Millisecond
	e.d.AutoUpdate.Running = func(context.Context) bool { return running.Load() }
	e.run(t)
	waitFor(t, func() bool { return len(e.start.calls()) == 1 })
	time.Sleep(100 * time.Millisecond)
	if n := len(e.alerts()); n != 0 {
		t.Fatalf("still running: %d alerts, want none", n)
	}
	running.Store(false) // the unit ended, and no result.json was left
	waitFor(t, func() bool { return len(e.alerts()) == 1 })
	a := e.alerts()[0].Alert
	if a.ID != "agent.update_failed" || !strings.Contains(a.Args["reason"], "without a result") {
		t.Errorf("alert = %+v", a)
	}
	time.Sleep(100 * time.Millisecond)
	if n := len(e.alerts()); n != 1 {
		t.Errorf("%d alerts, want exactly one", n)
	}
	e.stop()
}
