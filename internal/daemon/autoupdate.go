package daemon

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/yosefco3/shedu/internal/update"
	"github.com/yosefco3/shedu/internal/version"
	"github.com/yosefco3/shedu/internal/watch"
)

// AutoUpdate runs the nightly self-update. The daemon itself never writes its binary (the
// service runs with ProtectSystem=strict): it starts `shedu upgrade --auto` as a transient
// systemd unit, which downloads, verifies the release signature, swaps the binary and
// restarts the service. The outcome comes back through update.ResultFile, which the daemon
// checks every minute and turns into agent.updated / agent.update_failed.
type AutoUpdate struct {
	At   string // AUTO_UPDATE_AT: "" = fixed minute 03:00-05:00 from Host, "now", or "HH:MM"
	Host string // picks the fixed minute, so servers don't all update at once
	Dir  string // where result.json is; default update.DefaultDir

	// Start launches the upgrade; version "" lets it ask GitHub for the latest. Default:
	// systemd-run (StartTransient).
	Start func(ctx context.Context, version string) error
	// Poll is how often result.json is checked; default 1 minute.
	Poll time.Duration
	// LatestWait is how long "now" waits for the first heartbeat answer; default 60s.
	LatestWait time.Duration
	// ResultWithin is how long a started upgrade may take to leave its result before it
	// counts as failed (the upgrade itself gives up after 10 minutes); default 15 minutes.
	ResultWithin time.Duration
	// Running reports whether the shedu-update unit is still active; default systemctl.
	Running func(ctx context.Context) bool
}

// ErrUpdateRunning means the previous upgrade is still busy (for example still checking
// that the restarted service stays up): not a failure.
var ErrUpdateRunning = errors.New("an update is already running")

// ErrCannotStart means this host can't run the transient unit (no systemd): logged, not
// alerted every night.
var ErrCannotStart = errors.New("needs systemd")

// Time returns the next update time after now.
func (a *AutoUpdate) Time(now time.Time) time.Time {
	switch a.At {
	case "now":
		return now
	case "":
		next, _ := watch.NextAt(now, WindowMinute(a.Host))
		return next
	default:
		next, err := watch.NextAt(now, a.At)
		if err != nil {
			next, _ = watch.NextAt(now, WindowMinute(a.Host))
		}
		return next
	}
}

// Describe is the start-up log line.
func (a *AutoUpdate) Describe() string {
	switch a.At {
	case "now":
		return "auto-update: on, checking now (AUTO_UPDATE_AT=now), signed releases only"
	case "":
		return "auto-update: on, nightly at " + WindowMinute(a.Host) + " local time, signed releases only"
	}
	return "auto-update: on, nightly at " + a.At + " local time, signed releases only"
}

// WindowMinute is this host's fixed "HH:MM" between 03:00 and 04:59.
func WindowMinute(host string) string {
	h := fnv.New32a()
	h.Write([]byte(host)) //nolint:errcheck
	m := int(h.Sum32() % 120)
	return fmt.Sprintf("%02d:%02d", 3+m/60, m%60)
}

// StartTransient starts `shedu upgrade --auto` in its own transient unit, outside the
// service's sandbox and lifetime, and returns once it has started (not finished).
func StartTransient(ctx context.Context, v string) error {
	if os.Getenv("INVOCATION_ID") == "" {
		return fmt.Errorf("%w: not started by systemd", ErrCannotStart)
	}
	sr, err := exec.LookPath("systemd-run")
	if err != nil {
		return fmt.Errorf("%w: systemd-run not found", ErrCannotStart)
	}
	if unitActive(ctx) {
		return ErrUpdateRunning
	}
	args := []string{"--unit=shedu-update", "--collect", "--quiet", update.DefaultBinPath, "upgrade", "--auto"}
	if v != "" {
		args = append(args, "--version", v)
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(cctx, sr, args...).CombinedOutput(); err != nil {
		if strings.Contains(string(out), "already") {
			return ErrUpdateRunning
		}
		return fmt.Errorf("systemd-run: %v %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// unitActive reports whether shedu-update is still active (or starting or stopping).
func unitActive(ctx context.Context) bool {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(cctx, "systemctl", "is-active", "shedu-update").Output()
	switch strings.TrimSpace(string(out)) {
	case "active", "activating", "deactivating", "reloading":
		return true
	}
	return false
}

// autoUpdates waits for each update time and tries once.
func (d *Daemon) autoUpdates(ctx context.Context, events chan<- watch.Event) {
	a := *d.AutoUpdate
	var last time.Time
	for {
		next := a.Time(d.Clock())
		if !last.IsZero() && !next.After(last) {
			// The clock stepped back after the last try: never run twice for one slot.
			next = a.Time(last.Add(time.Minute))
		}
		t := time.NewTimer(next.Sub(d.Clock()))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		last = next
		d.tryUpdate(ctx, &a, events)
		if a.At == "now" {
			a.At = "" // "now" is once per start; then the nightly window
		}
	}
}

// tryUpdate starts the upgrade when a newer release is known (enrolled: from the
// heartbeat, so LATEST_AGENT_VERSION in the cloud decides the rollout) or may exist
// (not enrolled: the upgrade asks GitHub itself).
func (d *Daemon) tryUpdate(ctx context.Context, a *AutoUpdate, events chan<- watch.Event) {
	if d.Version == "dev" {
		d.Log.Println("auto-update: development build, skipped")
		return
	}
	target := ""
	if d.Cloud != nil {
		target = d.waitLatest(ctx, a)
		if !update.ValidVersion(target) || !version.Newer(target, d.Version) {
			d.Log.Printf("auto-update: up to date (running %s, latest %s)", d.Version, orNone(target))
			return
		}
	}
	start := a.Start
	if start == nil {
		start = StartTransient
	}
	err := start(ctx, target)
	switch {
	case errors.Is(err, ErrUpdateRunning):
		d.Log.Println("auto-update: an update is already running; nothing started")
		return
	case errors.Is(err, ErrCannotStart):
		d.Log.Printf("auto-update: %v; use sudo shedu upgrade, or set AUTO_UPDATE=no", err)
		return
	case err != nil:
		d.Log.Printf("auto-update: could not start the upgrade: %v", err)
		d.emit(ctx, events, watch.Event{Kind: watch.AgentUpdateFailed, Time: d.Clock(),
			Args: map[string]string{"from": d.Version, "version": target, "reason": "could not start the upgrade: " + err.Error()}})
		return
	}
	d.Log.Printf("auto-update: started shedu upgrade --auto (%s)", orLatest(target))
	d.upd.Lock()
	d.upd.started, d.upd.target = d.Clock(), target
	d.upd.Unlock()
}

// waitLatest returns the latest version from the heartbeat, waiting for the first answer
// when the update runs right after start-up.
func (d *Daemon) waitLatest(ctx context.Context, a *AutoUpdate) string {
	wait := a.LatestWait
	if wait <= 0 {
		wait = time.Minute
	}
	deadline := time.Now().Add(wait)
	for {
		if v := d.latestVersion(); v != "" || time.Now().After(deadline) {
			return v
		}
		select {
		case <-ctx.Done():
			return ""
		case <-time.After(time.Second):
		}
	}
}

// updateResults turns result.json, left by `shedu upgrade --auto`, into an event, and
// reports an upgrade that ended without leaving one.
func (d *Daemon) updateResults(ctx context.Context, events chan<- watch.Event) {
	poll := d.AutoUpdate.Poll
	if poll <= 0 {
		poll = time.Minute
	}
	within := d.AutoUpdate.ResultWithin
	if within <= 0 {
		within = 15 * time.Minute
	}
	running := d.AutoUpdate.Running
	if running == nil {
		running = unitActive
	}
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		r, ok := update.TakeResult(d.AutoUpdate.Dir)
		d.upd.Lock()
		started, target := d.upd.started, d.upd.target
		lost := !ok && !started.IsZero() && d.Clock().Sub(started) > within && !running(ctx)
		if ok || lost {
			d.upd.started = time.Time{}
		}
		d.upd.Unlock()
		switch {
		case lost:
			// The unit ended without a result: it could not run, or was killed.
			d.emit(ctx, events, watch.Event{Kind: watch.AgentUpdateFailed, Time: d.Clock(), Args: map[string]string{
				"from": d.Version, "version": target,
				"reason": "the update ended without a result (see: sudo journalctl -u shedu-update)"}})
		case ok:
			if ev, isEvent := resultEvent(r, d.Clock()); isEvent {
				d.emit(ctx, events, ev)
			} else if r.Skipped {
				d.Log.Printf("auto-update: skipped: %s", r.Reason)
			} else {
				d.Log.Printf("auto-update: up to date (running %s, latest %s)", d.Version, orNone(r.Version))
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func resultEvent(r update.RunResult, now time.Time) (watch.Event, bool) {
	args := map[string]string{"from": orNone(r.From), "version": r.Version} // "" reads "the latest release"
	switch {
	case r.OK && (r.UpToDate || r.Skipped):
		return watch.Event{}, false
	case r.OK:
		return watch.Event{Kind: watch.AgentUpdated, Time: now, Args: args}, true
	}
	args["reason"] = r.Reason
	if args["reason"] == "" {
		args["reason"] = "unknown error"
	}
	return watch.Event{Kind: watch.AgentUpdateFailed, Time: now, Args: args}, true
}

func (d *Daemon) emit(ctx context.Context, events chan<- watch.Event, ev watch.Event) {
	select {
	case events <- ev:
	case <-ctx.Done():
	}
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func orLatest(s string) string {
	if s == "" {
		return "latest from GitHub"
	}
	return s
}
