// Package daemon is the `shedu run` loop: watchers → rules → notifier, plus a
// daily report. It is deliberately boring: one goroutine per source, one
// sender, state saved after every change.
package daemon

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yosefco3/shedu/internal/config"
	"github.com/yosefco3/shedu/internal/finding"
	"github.com/yosefco3/shedu/internal/i18n"
	"github.com/yosefco3/shedu/internal/notify"
	"github.com/yosefco3/shedu/internal/version"
	"github.com/yosefco3/shedu/internal/watch"
	"github.com/yosefco3/shedu/pkg/cloudapi"
)

// Heartbeater is the part of cloud.Client the daemon calls directly.
type Heartbeater interface {
	Heartbeat(ctx context.Context, hb cloudapi.Heartbeat) (cloudapi.HeartbeatResponse, error)
}

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
	// AutoUpdate, when set, installs newer signed releases at night (AUTO_UPDATE=yes).
	AutoUpdate *AutoUpdate
	upd        struct { // the upgrade started last, until its result arrives
		sync.Mutex
		started time.Time
		target  string
	}

	// Cloud is set when the agent is enrolled. The daemon then sends a heartbeat every
	// HeartbeatEvery (default 5m) and a cloud-only report at start-up. Alerts reach the
	// cloud through Notifier (notify.Cloud), not through this field.
	Cloud          Heartbeater
	HeartbeatEvery time.Duration
	Addrs          func() []string // non-loopback addresses; default from net.InterfaceAddrs
	Uptime         func() int64    // host uptime in seconds; default /proc/uptime

	started time.Time
	latest  struct {
		sync.Mutex
		version string
	}

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

	d.started = d.Clock()
	if d.AutoUpdate != nil {
		wg.Add(2)
		go func() { defer wg.Done(); d.autoUpdates(ctx, events) }()
		go func() { defer wg.Done(); d.updateResults(ctx, events) }()
	}
	if d.Cloud != nil {
		wg.Add(1)
		go func() { defer wg.Done(); d.heartbeats(ctx) }()
		if d.RunCheck != nil {
			wg.Add(1)
			go func() { defer wg.Done(); d.startupReport(ctx) }()
		}
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
	m := ReportMessage(report, d.Cfg.Lang, i18n.T(d.Cfg.Lang, "daily", map[string]string{"host": report.Host}), d.Version)
	if v := d.latestVersion(); version.Newer(v, d.Version) {
		m.Text += "\n\n" + notify.Escape(i18n.T(d.Cfg.Lang, "update", map[string]string{"latest": v, "current": d.Version}))
	}
	d.send(ctx, m)
}

// startupReport runs the checks once and queues the result for the cloud only (no text,
// so Telegram stays quiet on every restart).
func (d *Daemon) startupReport(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	report := d.RunCheck(cctx)
	if ctx.Err() != nil {
		return
	}
	if d.Cfg.Hostname != "" {
		report.Host = d.Cfg.Hostname
	}
	m := ReportMessage(report, d.Cfg.Lang, "", d.Version)
	m.Text = ""
	d.send(ctx, m)
}

// heartbeats tells the cloud the agent is alive: one right away, then every
// HeartbeatEvery. A failing cloud costs one log line per 30 minutes, not one per beat.
func (d *Daemon) heartbeats(ctx context.Context) {
	every := d.HeartbeatEvery
	if every <= 0 {
		every = 5 * time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	var lastErrLog time.Time
	for {
		hctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		resp, err := d.Cloud.Heartbeat(hctx, d.heartbeat())
		cancel()
		switch {
		case err != nil && ctx.Err() == nil:
			if now := d.Clock(); now.Sub(lastErrLog) >= 30*time.Minute {
				d.Log.Printf("cloud: heartbeat failed: %v (next report of this in 30m)", err)
				lastErrLog = now
			}
		case err == nil:
			lastErrLog = time.Time{}
			d.noteLatest(resp.LatestVersion)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (d *Daemon) heartbeat() cloudapi.Heartbeat {
	names := []string{}
	if d.Auth != nil {
		names = append(names, "auth")
	}
	if d.Accounts != nil {
		names = append(names, "accounts")
	}
	for _, w := range d.Watchers {
		names = append(names, watcherName(w))
	}
	addrs := d.Addrs
	if addrs == nil {
		addrs = interfaceAddrs
	}
	uptime := d.Uptime
	if uptime == nil {
		uptime = func() int64 { return hostUptime(d.Clock().Sub(d.started)) }
	}
	return cloudapi.Heartbeat{
		Time: d.Clock().UTC(), AgentVersion: d.Version, UptimeSeconds: uptime(), Watchers: names,
		DirectTelegram: d.Cfg.TelegramEnabled(), Addrs: addrs(), Lang: string(d.Cfg.Lang),
	}
}

// noteLatest records the newest release the cloud knows of. It is display-only: one log
// line when it changes, and a line in the daily report. The nightly update (autoupdate.go)
// installs it if it is newer and signed.
func (d *Daemon) noteLatest(v string) {
	d.latest.Lock()
	changed := v != d.latest.version
	d.latest.version = v
	d.latest.Unlock()
	if changed && version.Newer(v, d.Version) {
		d.Log.Printf("cloud: a newer shedu is available: %s (running %s)", v, d.Version)
	}
}

func (d *Daemon) latestVersion() string {
	d.latest.Lock()
	defer d.latest.Unlock()
	return d.latest.version
}

// watcherName turns *watch.ProcWatcher into "ProcWatcher".
func watcherName(w watch.Runner) string {
	n := fmt.Sprintf("%T", w)
	if i := strings.LastIndex(n, "."); i >= 0 {
		n = n[i+1:]
	}
	return strings.TrimPrefix(n, "*")
}

// interfaceAddrs lists the non-loopback, non-link-local interface addresses.
func interfaceAddrs() []string {
	as, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	out := []string{}
	for _, a := range as {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP.IsLoopback() || ipn.IP.IsLinkLocalUnicast() {
			continue
		}
		out = append(out, ipn.IP.String())
	}
	return out
}

// hostUptime reads /proc/uptime; fallback is how long the daemon has run.
func hostUptime(fallback time.Duration) int64 {
	b, err := os.ReadFile("/proc/uptime")
	if err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			if v, err := strconv.ParseFloat(f[0], 64); err == nil {
				return int64(v)
			}
		}
	}
	return int64(fallback.Seconds())
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
