package watch

import (
	"context"
	"fmt"
	"io/fs"
	"math"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yosefco3/shedu/internal/config"
)

// destRec is what we remember about one destination of one program. Kept
// small on purpose: no per-connection history beyond the last few starts.
type destRec struct {
	Last   time.Time `json:"l"`
	Port   uint16    `json:"p"`
	Starts []int64   `json:"s,omitempty"` // unix seconds of the last connection starts
	Beacon time.Time `json:"b,omitempty"` // last beacon report
}

type outboundState struct {
	Since time.Time                      `json:"since"` // baseline taken
	Dest  map[string]map[string]*destRec `json:"dest"`  // program → ip → record
}

const (
	outboundStateFile = "outbound.json"
	maxStarts         = 8
	beaconMinStarts   = 6
	maxDestPerProgram = 256
	maxPrograms       = 128
)

// quietBeacons are agents whose whole job is to phone home on a timer.
// Process names are truncated to 15 characters by the kernel.
var quietBeacons = map[string]bool{
	"amazon-ssm-agen": true, "ssm-agent-worke": true, "droplet-agent": true, "google_guest_ag": true,
	"waagent": true, "shedu": true, "tailscaled": true, "cloudflared": true, "zabbix_agentd": true,
	"datadog-agent": true, "newrelic-infra": true, "snapd": true, "do-agent": true,
}

// OutboundWatcher maps which program talks to which outside address, and
// reports new destinations (OUTBOUND_ALERTS=all) and regular beacons (beacon|all).
type OutboundWatcher struct {
	Root     fs.FS // /proc: net/tcp{,6} and <pid>/fd links
	Interval time.Duration
	StateDir string
	T        config.Thresholds
	Clock    func() time.Time
	Log      func(format string, args ...any) // every new destination is logged, whatever the alert mode

	st       *outboundState
	prev     map[string]bool   // connection tuples seen last tick
	ipOwner  map[string]string // ip → last program seen talking to it
	lastSave time.Time
}

// NewOutboundWatcher returns the production watcher.
func NewOutboundWatcher(stateDir string, t config.Thresholds, logf func(string, ...any)) *OutboundWatcher {
	return &OutboundWatcher{Root: newProcFS("/proc"), Interval: 30 * time.Second, StateDir: stateDir, T: t, Clock: time.Now, Log: logf}
}

// Run polls until ctx ends.
func (w *OutboundWatcher) Run(ctx context.Context, _ *State, out chan<- Event, _ func() error) {
	runTicker(ctx, w.Interval, out, w.Tick)
}

// runTicker calls tick now and every interval, forwarding its events.
func runTicker(ctx context.Context, interval time.Duration, out chan<- Event, tick func() []Event) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		for _, ev := range tick() {
			select {
			case out <- ev:
			case <-ctx.Done():
				return
			}
		}
		select {
		case <-t.C:
		case <-ctx.Done():
			return
		}
	}
}

func (w *OutboundWatcher) now() time.Time {
	if w.Clock != nil {
		return w.Clock()
	}
	return time.Now()
}

func (w *OutboundWatcher) logf(format string, args ...any) {
	if w.Log != nil {
		w.Log(format, args...)
	}
}

// Tick takes one snapshot of the connection table.
func (w *OutboundWatcher) Tick() []Event {
	now := w.now()
	if w.st == nil {
		w.st = &outboundState{}
		loadSide(w.StateDir, outboundStateFile, w.st)
		if w.st.Dest == nil {
			w.st.Dest = map[string]map[string]*destRec{}
		}
		w.ipOwner = map[string]string{}
		for prog, ips := range w.st.Dest {
			for ip := range ips {
				w.ipOwner[ip] = prog
			}
		}
	}
	if w.T.OutboundAlerts == "" {
		w.T = config.ThresholdsFor(config.Normal)
	}
	conns, err := ReadConns(w.Root)
	if err != nil {
		return nil
	}
	baseline := w.st.Since.IsZero()
	firstTick := w.prev == nil
	owners := SocketOwners(w.Root)
	newWindow := time.Duration(w.T.OutboundNewDays) * 24 * time.Hour
	cur := map[string]bool{}
	changed := baseline
	var evs []Event

	for _, c := range Outgoing(conns) {
		ip := c.RemoteIP.String()
		tuple := fmt.Sprintf("%d-%s:%d", c.LocalPort, ip, c.RemotePort)
		cur[tuple] = true
		prog, pid := "?", 0
		if p, ok := owners[c.Inode]; ok && c.Inode != 0 {
			pid = p
			if b, err := fs.ReadFile(w.Root, path.Join(strconv.Itoa(p), "comm")); err == nil {
				prog = strings.TrimSpace(string(b))
			}
		}
		if prog == "?" && w.ipOwner[ip] != "" {
			prog = w.ipOwner[ip] // closed already: attribute to the last program seen there
		}
		if prog != "?" {
			w.ipOwner[ip] = prog
		}
		if w.st.Dest[prog] == nil {
			w.st.Dest[prog] = map[string]*destRec{}
		}
		rec := w.st.Dest[prog][ip]
		isNew := rec == nil || now.Sub(rec.Last) > newWindow
		if rec == nil {
			rec = &destRec{}
			w.st.Dest[prog][ip] = rec
		}
		rec.Last, rec.Port = now, c.RemotePort
		if !firstTick && !w.prev[tuple] {
			rec.Starts = append(rec.Starts, now.Unix())
			if len(rec.Starts) > maxStarts {
				rec.Starts = rec.Starts[len(rec.Starts)-maxStarts:]
			}
		}
		args := map[string]string{"comm": prog, "pid": strconv.Itoa(pid), "ip": ip, "port": strconv.Itoa(int(c.RemotePort))}
		if c.RemoteIP.IsPrivate() {
			args["private"] = "1"
		}
		if isNew && !baseline {
			changed = true
			w.logf("outbound: new destination %s:%d for %s (pid %d)", ip, c.RemotePort, prog, pid)
			if w.T.OutboundAlerts == config.OutboundAll {
				evs = append(evs, Event{Kind: OutboundNew, Detail: ip, Time: now, Args: args})
			}
		}
		if w.T.OutboundAlerts != config.OutboundOff && !c.RemoteIP.IsPrivate() && !quietBeacons[prog] &&
			now.Sub(rec.Beacon) > 24*time.Hour {
			if every, ok := IsBeacon(rec.Starts, w.Interval); ok {
				rec.Beacon = now
				changed = true
				args["count"] = strconv.Itoa(len(rec.Starts))
				args["every"] = every.Round(time.Second).String()
				evs = append(evs, Event{Kind: OutboundBeacon, Detail: ip, Time: now, Args: args})
			}
		}
	}
	w.prev = cur
	if baseline {
		w.st.Since = now
	}
	w.prune(now, newWindow)
	if changed || now.Sub(w.lastSave) > 10*time.Minute {
		_ = saveSide(w.StateDir, outboundStateFile, w.st)
		w.lastSave = now
	}
	return evs
}

// prune forgets destinations older than the "new" window and caps the map.
func (w *OutboundWatcher) prune(now time.Time, window time.Duration) {
	type kv struct {
		key  string
		last time.Time
	}
	var progs []kv
	for prog, ips := range w.st.Dest {
		var list []kv
		for ip, r := range ips {
			if now.Sub(r.Last) > window {
				delete(ips, ip)
				continue
			}
			list = append(list, kv{ip, r.Last})
		}
		if len(list) > maxDestPerProgram {
			sort.Slice(list, func(i, j int) bool { return list[i].last.After(list[j].last) })
			for _, e := range list[maxDestPerProgram:] {
				delete(ips, e.key)
			}
			list = list[:maxDestPerProgram]
		}
		if len(ips) == 0 {
			delete(w.st.Dest, prog)
			continue
		}
		newest := list[0].last
		for _, e := range list {
			if e.last.After(newest) {
				newest = e.last
			}
		}
		progs = append(progs, kv{prog, newest})
	}
	if len(progs) > maxPrograms {
		sort.Slice(progs, func(i, j int) bool { return progs[i].last.After(progs[j].last) })
		for _, e := range progs[maxPrograms:] {
			delete(w.st.Dest, e.key)
		}
	}
}

// IsBeacon decides whether connection start times look machine-regular: at
// least beaconMinStarts starts, a period of at least two polls, and every gap
// within one poll (plus 10%) of the mean. A heuristic: alerts say "maybe".
func IsBeacon(starts []int64, poll time.Duration) (time.Duration, bool) {
	if poll <= 0 {
		poll = 30 * time.Second
	}
	if len(starts) < beaconMinStarts {
		return 0, false
	}
	gaps := make([]float64, 0, len(starts)-1)
	sum := 0.0
	for i := 1; i < len(starts); i++ {
		g := float64(starts[i] - starts[i-1])
		gaps = append(gaps, g)
		sum += g
	}
	mean := sum / float64(len(gaps))
	if mean < 2*poll.Seconds() {
		return 0, false
	}
	tol := poll.Seconds() + 0.1*mean
	for _, g := range gaps {
		if math.Abs(g-mean) > tol {
			return 0, false
		}
	}
	return time.Duration(mean * float64(time.Second)), true
}
