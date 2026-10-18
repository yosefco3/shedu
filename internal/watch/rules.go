package watch

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yosefco3/shedu/internal/finding"
	"github.com/yosefco3/shedu/internal/i18n"
	"github.com/yosefco3/shedu/internal/notify"
)

// Alert is something worth interrupting the owner for.
type Alert struct {
	ID       string // i18n key, e.g. "alert.bruteforce"
	Severity finding.Severity
	Args     map[string]string
	Fix      string
	Key      string // rate-limit key, e.g. "bruteforce:1.2.3.4"
	Time     time.Time
}

// Telegram renders the alert as an HTML message.
func (a Alert) Telegram(lang i18n.Lang) string {
	m := i18n.Render(lang, a.ID, a.Args)
	var b strings.Builder
	fmt.Fprintf(&b, "%s <b>%s</b>\n%s", finding.Icon(a.Severity), notify.Escape(m.Title), notify.Escape(m.Explain))
	if a.Fix != "" {
		fmt.Fprintf(&b, "\n<code>%s</code>", notify.Escape(a.Fix))
	}
	return b.String()
}

type failRec struct {
	t    time.Time
	user string
}

// Rules turns Events into Alerts, remembering just enough to avoid noise.
type Rules struct {
	Threshold int           // failures per IP that count as brute force (default 5)
	Window    time.Duration // over this period (default 10m)
	Cooldown  time.Duration // same alert key at most once per this (default 1h)
	Clock     func() time.Time
	fails     map[string][]failRec // ip → recent failures (memory only)
}

// NewRules returns rules with the given threshold and default timings.
func NewRules(threshold int) *Rules {
	if threshold < 1 {
		threshold = 5
	}
	return &Rules{Threshold: threshold, Window: 10 * time.Minute, Cooldown: time.Hour, Clock: time.Now}
}

func (r *Rules) now() time.Time {
	if r.Clock != nil {
		return r.Clock()
	}
	return time.Now()
}

// Feed processes one event. It mutates st (known IPs, sudo users, rate limits);
// the caller persists st. At most one alert per event.
func (r *Rules) Feed(ev Event, st *State) (Alert, bool) {
	if r.fails == nil {
		r.fails = map[string][]failRec{}
	}
	now := r.now()
	switch ev.Kind {
	case LoginFail, InvalidUser:
		return r.onFail(ev, st, now)
	case LoginOK:
		return r.onLogin(ev, st, now)
	case SudoCmd:
		if len(st.SudoUsers) == 0 {
			st.SudoUsers[ev.User] = now
			return Alert{}, false
		}
		if _, known := st.SudoUsers[ev.User]; known {
			return Alert{}, false
		}
		st.SudoUsers[ev.User] = now
		return r.emit(st, now, Alert{ID: "alert.sudo_new_user", Severity: finding.Medium, Key: "sudo_new:" + ev.User,
			Args: map[string]string{"user": ev.User, "command": ev.Detail}})
	case SudoFail:
		return r.emit(st, now, Alert{ID: "alert.sudo_fail", Severity: finding.Low, Key: "sudo_fail:" + ev.User,
			Args: map[string]string{"user": ev.User, "detail": ev.Detail}})
	case UserAdded:
		return r.direct(now, Alert{ID: "alert.user_added", Severity: finding.High,
			Args: map[string]string{"user": ev.User, "uid": ev.Detail}, Fix: "sudo last " + ev.User + " ; sudo userdel -r " + ev.User})
	case UserRemoved:
		return r.direct(now, Alert{ID: "alert.user_removed", Severity: finding.Low, Args: map[string]string{"user": ev.User}})
	case KeyAdded:
		fp, comment, _ := strings.Cut(ev.Detail, " ")
		return r.direct(now, Alert{ID: "alert.key_added", Severity: finding.High,
			Args: map[string]string{"user": ev.User, "fp": fp, "comment": comment}, Fix: "sudo nano " + authorizedKeysPath(ev.User)})
	case KeyRemoved:
		fp, _, _ := strings.Cut(ev.Detail, " ")
		return r.direct(now, Alert{ID: "alert.key_removed", Severity: finding.Info, Args: map[string]string{"user": ev.User, "fp": fp}})
	case SudoersChanged:
		return r.direct(now, Alert{ID: "alert.sudoers_changed", Severity: finding.High, Args: map[string]string{"diff": ev.Detail}})
	case ProcSuspicious:
		reason := ev.Args["reason"]
		return r.emit(st, now, Alert{ID: "alert.proc_" + reason, Severity: finding.High, Key: "proc:" + ev.Args["pid"] + ":" + reason,
			Args: ev.Args, Fix: ProcFix(reason, ev.Args["pid"])})
	case OutboundNew:
		return r.emit(st, now, Alert{ID: "alert.outbound_new", Severity: finding.Low, Key: "out:" + ev.Args["comm"] + ":" + ev.Args["ip"],
			Args: ev.Args, Fix: "sudo ss -tnp dst " + ev.Args["ip"]})
	case ProcLineage:
		return r.emit(st, now, Alert{ID: "alert.proc_lineage", Severity: finding.High, Key: "lineage:" + ev.Args["pid"],
			Args: ev.Args, Fix: ProcFix(ReasonTmpExec, ev.Args["pid"])})
	case MassFileChange:
		secs, _ := strconv.Atoi(ev.Args["seconds"])
		return r.emit(st, now, Alert{ID: "alert.massfile", Severity: finding.Medium, Key: "massfile:" + ev.Args["dir"], Args: ev.Args,
			Fix: fmt.Sprintf("sudo find %s -type f -mmin -%d | head -50", ev.Args["dir"], secs/60+1)})
	case MinerSuspected:
		pid := ev.Args["pid"]
		return r.emit(st, now, Alert{ID: "alert.miner", Severity: finding.High, Key: "miner:" + pid, Args: ev.Args,
			Fix: "top -b -n1 | head -15; sudo ls -l /proc/" + pid + "/exe && sudo kill " + pid})
	case PreloadChanged:
		if ev.Args["source"] == "file" {
			return r.direct(now, Alert{ID: "alert.preload_file", Severity: finding.Critical, Args: ev.Args, Fix: PreloadFix})
		}
		return r.emit(st, now, Alert{ID: "alert.preload_env", Severity: finding.High, Key: "preload:" + ev.Args["pid"], Args: ev.Args,
			Fix: PreloadEnvFix(ev.Args["pid"])})
	case ClamDetected:
		return r.direct(now, Alert{ID: "alert.clamav", Severity: finding.High, Args: ev.Args,
			Fix: "sudo mkdir -p /root/quarantine && sudo mv " + ev.Args["paths"] + " /root/quarantine/ && sudo chmod -R 000 /root/quarantine"})
	case PersistenceNew:
		sev := finding.Medium
		if ev.Args["user_level"] != "" {
			sev = finding.High // packages never write here
		}
		return r.direct(now, Alert{ID: "alert.persistence_new", Severity: sev, Args: ev.Args, Fix: ev.Args["fix"]})
	case OutboundBeacon:
		return r.emit(st, now, Alert{ID: "alert.outbound_beacon", Severity: finding.Medium, Key: "beacon:" + ev.Args["comm"] + ":" + ev.Args["ip"],
			Args: ev.Args, Fix: "sudo ss -tnp dst " + ev.Args["ip"]})
	}
	return Alert{}, false
}

func (r *Rules) onFail(ev Event, st *State, now time.Time) (Alert, bool) {
	recs := r.prune(ev.IP, now)
	recs = append(recs, failRec{t: now, user: ev.User})
	r.fails[ev.IP] = recs
	if len(recs) < r.Threshold {
		return Alert{}, false
	}
	return r.emit(st, now, Alert{ID: "alert.bruteforce", Severity: finding.High, Key: "bruteforce:" + ev.IP,
		Args: map[string]string{"ip": ev.IP, "count": strconv.Itoa(len(recs)), "users": topUsers(recs, 3), "minutes": strconv.Itoa(int(r.Window.Minutes()))}})
}

func (r *Rules) onLogin(ev Event, st *State, now time.Time) (Alert, bool) {
	ip := net.ParseIP(ev.IP)
	if ip != nil && ip.IsLoopback() {
		return Alert{}, false
	}
	args := map[string]string{"user": ev.User, "ip": ev.IP, "method": ev.Method}
	if ip != nil && ip.IsPrivate() {
		args["private"] = "1"
	}
	if len(r.prune(ev.IP, now)) >= r.Threshold {
		delete(r.fails, ev.IP)
		if _, known := st.KnownIPs[ev.IP]; !known {
			st.KnownIPs[ev.IP] = now
		}
		return r.emit(st, now, Alert{ID: "alert.login_after_bruteforce", Severity: finding.Critical, Key: "login_after_bf:" + ev.IP, Args: args})
	}
	if len(st.KnownIPs) == 0 { // first login ever seen: learn, don't alarm
		st.KnownIPs[ev.IP] = now
		return Alert{}, false
	}
	if _, known := st.KnownIPs[ev.IP]; known {
		return Alert{}, false
	}
	st.KnownIPs[ev.IP] = now
	return r.emit(st, now, Alert{ID: "alert.login_new_ip", Severity: finding.Medium, Key: "newip:" + ev.IP, Args: args})
}

// prune drops failures older than Window for ip and returns the rest.
func (r *Rules) prune(ip string, now time.Time) []failRec {
	recs := r.fails[ip]
	kept := recs[:0]
	for _, f := range recs {
		if now.Sub(f.t) <= r.Window {
			kept = append(kept, f)
		}
	}
	if len(kept) == 0 {
		delete(r.fails, ip)
		return nil
	}
	r.fails[ip] = kept
	return kept
}

// emit applies the per-key cooldown recorded in st.
func (r *Rules) emit(st *State, now time.Time, a Alert) (Alert, bool) {
	if last, ok := st.LastAlerts[a.Key]; ok && now.Sub(last) < r.Cooldown {
		return Alert{}, false
	}
	st.LastAlerts[a.Key] = now
	a.Time = now
	return a, true
}

// direct is for account changes: every one is reported, no rate limit.
func (r *Rules) direct(now time.Time, a Alert) (Alert, bool) {
	a.Time = now
	a.Key = a.ID
	return a, true
}

func topUsers(recs []failRec, n int) string {
	count := map[string]int{}
	for _, f := range recs {
		count[f.user]++
	}
	users := make([]string, 0, len(count))
	for u := range count {
		users = append(users, u)
	}
	sort.Slice(users, func(i, j int) bool {
		if count[users[i]] != count[users[j]] {
			return count[users[i]] > count[users[j]]
		}
		return users[i] < users[j]
	})
	if len(users) > n {
		users = users[:n]
	}
	return strings.Join(users, ", ")
}

func authorizedKeysPath(user string) string {
	if user == "root" {
		return "/root/.ssh/authorized_keys"
	}
	return "/home/" + user + "/.ssh/authorized_keys"
}

// ProcFix is the copy-pasteable response to a suspicious process: look first,
// keep evidence when the file is gone, then stop it.
func ProcFix(reason, pid string) string {
	if reason == ReasonDeletedExec {
		return "sudo cp /proc/" + pid + "/exe /root/suspect-" + pid + ".bin && sudo kill " + pid
	}
	return "sudo ls -l /proc/" + pid + "/exe /proc/" + pid + "/cwd && sudo kill " + pid
}

// PreloadEnvFix shows the injected value and the library behind it.
func PreloadEnvFix(pid string) string {
	return "sudo tr '\\0' '\\n' < /proc/" + pid + "/environ | grep LD_PRELOAD"
}
