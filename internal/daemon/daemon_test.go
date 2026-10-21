package daemon

import (
	"context"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yosefco3/shedu/internal/config"
	"github.com/yosefco3/shedu/internal/finding"
	"github.com/yosefco3/shedu/internal/i18n"
	"github.com/yosefco3/shedu/internal/notify"
	"github.com/yosefco3/shedu/internal/watch"
)

func TestNextDaily(t *testing.T) {
	loc := time.FixedZone("IL", 3*3600)
	now := time.Date(2026, 10, 17, 7, 59, 0, 0, loc)
	cases := []struct {
		now   time.Time
		hhmm  string
		want  time.Time
		isErr bool
	}{
		{now, "08:00", time.Date(2026, 10, 17, 8, 0, 0, 0, loc), false},
		{time.Date(2026, 10, 17, 8, 0, 0, 0, loc), "08:00", time.Date(2026, 10, 18, 8, 0, 0, 0, loc), false},
		{time.Date(2026, 10, 17, 23, 30, 0, 0, loc), "08:00", time.Date(2026, 10, 18, 8, 0, 0, 0, loc), false},
		{now, "8am", time.Time{}, true},
		{now, "25:00", time.Time{}, true},
	}
	for _, c := range cases {
		got, err := NextDaily(c.now, c.hhmm)
		if (err != nil) != c.isErr || (!c.isErr && !got.Equal(c.want)) {
			t.Errorf("NextDaily(%v, %q) = %v, %v; want %v", c.now, c.hhmm, got, err, c.want)
		}
	}
}

type fakeSource struct{ ch chan watch.Event }

func (f *fakeSource) Events(ctx context.Context) (<-chan watch.Event, error) { return f.ch, nil }

type recorder struct {
	mu   sync.Mutex
	msgs []string
	full []notify.Message
}

func (r *recorder) Send(_ context.Context, m notify.Message) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.msgs = append(r.msgs, m.Text)
	r.full = append(r.full, m)
	return nil
}

func (r *recorder) count() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.msgs) }

func TestDaemonPipeline(t *testing.T) {
	src := &fakeSource{ch: make(chan watch.Event)}
	rec := &recorder{}
	dir := t.TempDir()
	d := &Daemon{
		Cfg:      config.Config{Lang: i18n.En, Hostname: "web-1", StateDir: dir, DailyReportAt: ""},
		Notifier: rec,
		Auth:     src,
		Rules:    watch.NewRules(5),
		State:    &watch.State{KnownIPs: map[string]time.Time{}, SudoUsers: map[string]time.Time{}, LastAlerts: map[string]time.Time{}},
		Log:      log.New(io.Discard, "", 0),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- d.Run(ctx) }()

	// fresh state → "connected" message
	waitFor(t, func() bool { return rec.count() == 1 })
	if !strings.Contains(rec.msgs[0], "web-1") {
		t.Errorf("start message = %q", rec.msgs[0])
	}
	for i := 0; i < 5; i++ {
		src.ch <- watch.Event{Kind: watch.LoginFail, IP: "1.2.3.4", User: "root"}
	}
	waitFor(t, func() bool { return rec.count() == 2 })
	if !strings.Contains(rec.msgs[1], "1.2.3.4") || !strings.Contains(rec.msgs[1], "<b>") {
		t.Errorf("alert = %q", rec.msgs[1])
	}
	rec.mu.Lock()
	m := rec.full[1]
	rec.mu.Unlock()
	if m.Kind != notify.KindAlert || m.Alert == nil || m.UID == "" || m.UID != m.Alert.UID ||
		m.Alert.ID != "alert.bruteforce" || m.Alert.Text["he"].Title == "" || m.Alert.Text["en"].Title == "" {
		t.Errorf("structured alert = %+v", m)
	}
	if rec.full[0].Kind != notify.KindText {
		t.Errorf("start message kind = %q", rec.full[0].Kind)
	}
	src.ch <- watch.Event{Kind: watch.LoginFail, IP: "1.2.3.4", User: "root"}
	time.Sleep(50 * time.Millisecond)
	if rec.count() != 2 {
		t.Error("6th failure must be rate-limited")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	if _, err := os.Stat(filepath.Join(dir, "state.json")); err != nil {
		t.Error("state must be flushed on shutdown")
	}
	st, _ := watch.LoadState(dir)
	if _, ok := st.LastAlerts["bruteforce:1.2.3.4"]; !ok {
		t.Error("rate-limit record must be persisted")
	}
}

func TestDaemonNoStartMessageWhenNotFresh(t *testing.T) {
	rec := &recorder{}
	d := &Daemon{
		Cfg:      config.Config{Lang: i18n.He, Hostname: "h"},
		Notifier: rec,
		Rules:    watch.NewRules(5),
		State:    &watch.State{KnownIPs: map[string]time.Time{"1.1.1.1": time.Now()}, SudoUsers: map[string]time.Time{}, LastAlerts: map[string]time.Time{}},
		Log:      log.New(io.Discard, "", 0),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_ = d.Run(ctx)
	if rec.count() != 0 {
		t.Errorf("restart of a known state must be silent, got %v", rec.msgs)
	}
}

func TestDaemonDailyReport(t *testing.T) {
	rec := &recorder{}
	now := time.Now()
	at := now.Add(300 * time.Millisecond).Format("15:04")
	// NextDaily resolves to minute precision; make the timer fire within the test
	// by faking the clock so that "now" is a few hundred ms before the target.
	target, _ := NextDaily(now, at)
	d := &Daemon{
		Cfg:      config.Config{Lang: i18n.En, Hostname: "h", DailyReportAt: at},
		Notifier: rec,
		Rules:    watch.NewRules(5),
		State:    &watch.State{KnownIPs: map[string]time.Time{"x": now}, SudoUsers: map[string]time.Time{}, LastAlerts: map[string]time.Time{}},
		Clock:    func() time.Time { return target.Add(-200 * time.Millisecond) },
		RunCheck: func(context.Context) finding.Report {
			return finding.Report{Host: "h", Findings: []finding.Finding{{ID: "updates.no_auto", Severity: finding.Medium}}}
		},
		Log: log.New(io.Discard, "", 0),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go d.Run(ctx)
	waitFor(t, func() bool { return rec.count() == 1 })
	if !strings.Contains(rec.msgs[0], "Daily report") || !strings.Contains(rec.msgs[0], "92/100") {
		t.Errorf("daily = %q", rec.msgs[0])
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}

// oneShot is a phase-2 watcher that reports one event, then idles.
type oneShot struct{ ev watch.Event }

func (o oneShot) Run(ctx context.Context, _ *watch.State, out chan<- watch.Event, _ func() error) {
	select {
	case out <- o.ev:
	case <-ctx.Done():
		return
	}
	<-ctx.Done()
}

func TestDaemonRunsWatchers(t *testing.T) {
	rec := &recorder{}
	st := &watch.State{KnownIPs: map[string]time.Time{"1.2.3.4": time.Now()}, SudoUsers: map[string]time.Time{}, LastAlerts: map[string]time.Time{}}
	d := &Daemon{
		Cfg:      config.Config{Lang: i18n.He, Hostname: "web-1", StateDir: t.TempDir()},
		Notifier: rec,
		Rules:    watch.NewRules(5),
		State:    st,
		Log:      log.New(io.Discard, "", 0),
		Watchers: []watch.Runner{oneShot{watch.Event{Kind: watch.ProcSuspicious, Args: map[string]string{
			"reason": watch.ReasonTmpExec, "pid": "4242", "exe": "/tmp/x", "comm": "x", "user": "www-data", "cmd": "/tmp/x 600"}}}},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- d.Run(ctx) }()
	waitFor(t, func() bool { return rec.count() == 1 })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	msg := rec.msgs[0]
	if !strings.Contains(msg, "תוכנה רצה מתיקייה זמנית: /tmp/x") || !strings.Contains(msg, "<code>sudo ls -l /proc/4242/exe") {
		t.Errorf("alert = %q", msg)
	}
}
