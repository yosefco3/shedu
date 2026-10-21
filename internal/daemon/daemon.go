// Package daemon is the `shedu run` loop: watchers → rules → notifier, plus a
// daily report. It is deliberately boring: one goroutine per source, one
// sender, state saved after every change.
package daemon

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/yosefco3/shedu/internal/config"
	"github.com/yosefco3/shedu/internal/finding"
	"github.com/yosefco3/shedu/internal/i18n"
	"github.com/yosefco3/shedu/internal/notify"
	"github.com/yosefco3/shedu/internal/watch"
)

// Daemon wires the pieces together. Every field is replaceable for tests.
type Daemon struct {
	Cfg      config.Config
	Notifier notify.Notifier
	Auth     watch.Source           // login/sudo events
	Accounts *watch.AccountsWatcher // user/key/sudoers events
	Watchers []watch.Runner         // phase-2 watchers (processes, network, persistence, ...)
	Rules    *watch.Rules
	State    *watch.State
	Clock    func() time.Time
	RunCheck func(ctx context.Context) finding.Report
	Log      *log.Logger
	Version  string // agent version, carried in cloud reports

	// Backoff bounds for restarting a source that ended (journalctl died, file vanished).
	MinBackoff, MaxBackoff time.Duration
	// Backoff bounds for re-sending a message that failed (default 10s .. 5m).
	RetryMin, RetryMax time.Duration

	out *outbox
}

// Run blocks until ctx is done. It returns after the state has been saved.
func (d *Daemon) Run(ctx context.Context) error {
	if d.Clock == nil {
		d.Clock = time.Now
	}
	if d.Log == nil {
		d.Log = log.Default()
	}
	if d.MinBackoff <= 0 {
		d.MinBackoff = time.Second
	}
	if d.MaxBackoff <= 0 {
		d.MaxBackoff = 30 * time.Second
	}
	if d.State == nil {
		d.State = &watch.State{}
	}

	saver := newSaver(d.State, d.Cfg.StateDir, d.Log)
	defer saver.flush()

	var wg sync.WaitGroup
	if d.Notifier != nil {
		d.out = newOutbox(d.Notifier, d.Log, d.RetryMin, d.RetryMax)
		wg.Add(1)
		go func() { defer wg.Done(); d.out.run(ctx) }()
	}

	events := make(chan watch.Event, 256)

	if d.Auth != nil {
		wg.Add(1)
		go func() { defer wg.Done(); d.pump(ctx, events) }()
	}
	if d.Accounts != nil {
		wg.Add(1)
		go func() { defer wg.Done(); d.Accounts.Run(ctx, d.State, events, saver.request) }()
	}
	for _, w := range d.Watchers {
		wg.Add(1)
		go func(w watch.Runner) { defer wg.Done(); w.Run(ctx, d.State, events, saver.request) }(w)
	}

	if d.State.Fresh() {
		d.send(ctx, notify.TextMessage(i18n.T(d.Cfg.Lang, "connected", map[string]string{"host": d.Cfg.Hostname})))
	}

	var daily <-chan time.Time
	var dailyTimer *time.Timer
	if d.Cfg.DailyReportAt != "" && d.RunCheck != nil {
		if next, err := NextDaily(d.Clock(), d.Cfg.DailyReportAt); err == nil {
			dailyTimer = time.NewTimer(next.Sub(d.Clock()))
			daily = dailyTimer.C
		} else {
			d.Log.Printf("daily report disabled: %v", err)
		}
	}

	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return nil
		case ev := <-events:
			if alert, ok := d.Rules.Feed(ev, d.State); ok {
				d.send(ctx, AlertMessage(alert, d.Cfg.Lang))
			}
			saver.request()
		case <-daily:
			d.sendDaily(ctx)
			next, _ := NextDaily(d.Clock(), d.Cfg.DailyReportAt)
			dailyTimer.Reset(next.Sub(d.Clock()))
		}
	}
}

// pump forwards events from the auth source, restarting it with backoff when it ends.
func (d *Daemon) pump(ctx context.Context, out chan<- watch.Event) {
	backoff := d.MinBackoff
	for ctx.Err() == nil {
		ch, err := d.Auth.Events(ctx)
		if err != nil {
			d.Log.Printf("auth source: %v (retry in %s)", err, backoff)
		} else {
			started := d.Clock()
		drain:
			for {
				select {
				case ev, ok := <-ch:
					if !ok {
						break drain
					}
					select {
					case out <- ev:
					case <-ctx.Done():
						return
					}
				case <-ctx.Done():
					return
				}
			}
			if d.Clock().Sub(started) > time.Minute {
				backoff = d.MinBackoff // it ran fine for a while: reset
			}
			d.Log.Printf("auth source ended (restart in %s)", backoff)
		}
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return
		}
		if backoff *= 2; backoff > d.MaxBackoff {
			backoff = d.MaxBackoff
		}
	}
}

// send queues a message for delivery; the outbox retries until it gets through.
func (d *Daemon) send(_ context.Context, m notify.Message) {
	if d.out != nil {
		d.out.put(m)
	}
}

// AlertMessage carries an alert both as Telegram text and as a cloud event.
func AlertMessage(a watch.Alert, lang i18n.Lang) notify.Message {
	ev := a.Cloud()
	return notify.Message{UID: ev.UID, Kind: notify.KindAlert, Text: a.Telegram(lang), Alert: &ev}
}

// ReportMessage carries a check report both as Telegram text (with a heading) and as a
// cloud report. The UID is derived from host and time, like an alert's.
func ReportMessage(r finding.Report, lang i18n.Lang, heading, version string) notify.Message {
	cr := finding.Cloud(r, version)
	text := finding.Telegram(r, lang, 5)
	if heading != "" {
		text = heading + "\n" + text
	}
	return notify.Message{UID: "report:" + r.Host + ":" + r.Time.UTC().Format(time.RFC3339Nano), Kind: notify.KindReport, Text: text, Report: &cr}
}

func (d *Daemon) sendDaily(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	report := d.RunCheck(cctx)
	if d.Cfg.Hostname != "" {
		report.Host = d.Cfg.Hostname
	}
	d.send(ctx, ReportMessage(report, d.Cfg.Lang, i18n.T(d.Cfg.Lang, "daily", map[string]string{"host": report.Host}), d.Version))
}

// NextDaily returns the next occurrence of "HH:MM" strictly after now, in now's location.
func NextDaily(now time.Time, hhmm string) (time.Time, error) {
	next, err := watch.NextAt(now, hhmm)
	if err != nil {
		return time.Time{}, fmt.Errorf("DAILY_REPORT_AT %v", err)
	}
	return next, nil
}

// saver debounces state writes: many events in a burst → one write.
type saver struct {
	mu      sync.Mutex
	st      *watch.State
	dir     string
	log     *log.Logger
	pending bool
	timer   *time.Timer
}

func newSaver(st *watch.State, dir string, l *log.Logger) *saver {
	return &saver{st: st, dir: dir, log: l}
}

func (s *saver) request() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dir == "" {
		return nil
	}
	s.pending = true
	if s.timer == nil {
		s.timer = time.AfterFunc(2*time.Second, s.flush)
	}
	return nil
}

func (s *saver) flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.timer = nil
	if !s.pending || s.dir == "" {
		return
	}
	s.pending = false
	if err := s.st.Save(s.dir); err != nil {
		s.log.Printf("save state: %v", err)
	}
}
