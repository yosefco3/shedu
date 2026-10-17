package watch

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// AccountsWatcher snapshots users, authorized SSH keys and sudoers every
// Interval and emits an Event for each difference. Simple polling: no inotify,
// no kernel hooks, nothing to break.
type AccountsWatcher struct {
	Passwd   func() ([]byte, error)            // /etc/passwd
	HomeKeys func(home string) ([]byte, error) // authorized_keys(+2) of one home, nil if none
	Sudoers  func() ([]byte, error)            // /etc/sudoers + sudoers.d/* concatenated
	Interval time.Duration                     // default 60s
	StateDir string                            // where sudoers.last is kept for diffs
}

// NewAccountsWatcher returns the production collector.
func NewAccountsWatcher(stateDir string) *AccountsWatcher {
	return &AccountsWatcher{
		Passwd: func() ([]byte, error) { return os.ReadFile("/etc/passwd") },
		HomeKeys: func(home string) ([]byte, error) {
			var out []byte
			for _, name := range []string{"authorized_keys", "authorized_keys2"} {
				b, err := os.ReadFile(filepath.Join(home, ".ssh", name))
				if err == nil {
					out = append(out, b...)
					out = append(out, '\n')
				}
			}
			return out, nil
		},
		Sudoers: func() ([]byte, error) {
			paths, _ := filepath.Glob("/etc/sudoers.d/*")
			sort.Strings(paths)
			paths = append([]string{"/etc/sudoers"}, paths...)
			var out []byte
			for _, p := range paths {
				b, err := os.ReadFile(p)
				if err != nil {
					if errors.Is(err, os.ErrNotExist) {
						continue
					}
					return nil, err
				}
				out = append(out, []byte("# "+p+"\n")...)
				out = append(out, b...)
				out = append(out, '\n')
			}
			return out, nil
		},
		Interval: time.Minute,
		StateDir: stateDir,
	}
}

var systemShells = map[string]bool{"/usr/sbin/nologin": true, "/sbin/nologin": true, "/bin/false": true, "/usr/bin/false": true, "/bin/sync": true, "/sbin/halt": true, "/sbin/shutdown": true}

// isHuman decides whether a passwd entry matters: real people (uid ≥ 1000),
// root, or anything with a login shell. Package accounts like _apt are ignored.
func isHuman(name string, u UserInfo) bool {
	return u.UID >= 1000 || name == "root" || !systemShells[u.Shell]
}

// Snapshot builds the comparable picture from raw inputs.
func Snapshot(passwd []byte, homeKeys func(string) ([]byte, error), sudoers []byte, now time.Time) AccountsSnapshot {
	snap := AccountsSnapshot{Users: map[string]UserInfo{}, Keys: map[string][]string{}, Taken: now}
	sc := bufio.NewScanner(bytes.NewReader(passwd))
	for sc.Scan() {
		f := strings.Split(sc.Text(), ":")
		if len(f) < 7 || f[0] == "" {
			continue
		}
		uid, _ := strconv.Atoi(f[2])
		u := UserInfo{UID: uid, Shell: f[6], Home: f[5]}
		if !isHuman(f[0], u) {
			continue
		}
		snap.Users[f[0]] = u
		if homeKeys != nil {
			if b, err := homeKeys(u.Home); err == nil && len(b) > 0 {
				snap.Keys[f[0]] = Fingerprints(b)
			}
		}
	}
	sum := sha256.Sum256(sudoers)
	snap.Sudoers = hex.EncodeToString(sum[:])
	return snap
}

// Fingerprints returns "SHA256:... comment" for each key line, sorted.
func Fingerprints(authorizedKeys []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(authorizedKeys))
	for sc.Scan() {
		if fp, comment, ok := Fingerprint(sc.Text()); ok {
			if comment != "" {
				fp += " " + comment
			}
			out = append(out, fp)
		}
	}
	sort.Strings(out)
	return out
}

var keyTypes = map[string]bool{"ssh-ed25519": true, "ssh-rsa": true, "ecdsa-sha2-nistp256": true, "ecdsa-sha2-nistp384": true, "ecdsa-sha2-nistp521": true, "ssh-dss": true, "sk-ssh-ed25519@openssh.com": true, "sk-ecdsa-sha2-nistp256@openssh.com": true}

// Fingerprint computes the OpenSSH SHA256 fingerprint of one authorized_keys
// line (options prefix allowed), exactly as `ssh-keygen -lf` prints it.
func Fingerprint(line string) (fp, comment string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	fields := strings.Fields(line)
	// skip an options field such as from="1.2.3.4",no-pty
	for len(fields) > 0 && !keyTypes[fields[0]] {
		fields = fields[1:]
	}
	if len(fields) < 2 {
		return "", "", false
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return "", "", false
	}
	sum := sha256.Sum256(blob)
	fp = "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
	return fp, strings.Join(fields[2:], " "), true
}

// Diff emits events for every change between two snapshots.
func Diff(old, cur AccountsSnapshot, sudoersDiff string, now time.Time) []Event {
	var evs []Event
	for name, u := range cur.Users {
		if _, ok := old.Users[name]; !ok {
			evs = append(evs, Event{Kind: UserAdded, User: name, Detail: strconv.Itoa(u.UID), Time: now})
		}
	}
	for name := range old.Users {
		if _, ok := cur.Users[name]; !ok {
			evs = append(evs, Event{Kind: UserRemoved, User: name, Time: now})
		}
	}
	users := map[string]bool{}
	for u := range old.Keys {
		users[u] = true
	}
	for u := range cur.Keys {
		users[u] = true
	}
	for u := range users {
		o, c := toSet(old.Keys[u]), toSet(cur.Keys[u])
		for k := range c {
			if !o[k] {
				evs = append(evs, Event{Kind: KeyAdded, User: u, Detail: k, Time: now})
			}
		}
		for k := range o {
			if !c[k] {
				evs = append(evs, Event{Kind: KeyRemoved, User: u, Detail: k, Time: now})
			}
		}
	}
	if old.Sudoers != "" && old.Sudoers != cur.Sudoers {
		evs = append(evs, Event{Kind: SudoersChanged, Detail: sudoersDiff, Time: now})
	}
	sort.Slice(evs, func(i, j int) bool {
		if evs[i].Kind != evs[j].Kind {
			return evs[i].Kind < evs[j].Kind
		}
		return evs[i].User+evs[i].Detail < evs[j].User+evs[j].Detail
	})
	return evs
}

func toSet(ss []string) map[string]bool {
	m := map[string]bool{}
	for _, s := range ss {
		m[s] = true
	}
	return m
}

// SimpleDiff lists removed (-) and added (+) lines, ignoring blanks and
// comments, capped at max lines so an alert stays readable.
func SimpleDiff(old, cur string, max int) string {
	norm := func(s string) map[string]bool {
		m := map[string]bool{}
		for _, l := range strings.Split(s, "\n") {
			l = strings.TrimSpace(l)
			if l != "" && !strings.HasPrefix(l, "#") {
				m[l] = true
			}
		}
		return m
	}
	o, c := norm(old), norm(cur)
	var lines []string
	for l := range o {
		if !c[l] {
			lines = append(lines, "- "+l)
		}
	}
	for l := range c {
		if !o[l] {
			lines = append(lines, "+ "+l)
		}
	}
	sort.Strings(lines)
	if len(lines) > max {
		lines = append(lines[:max], "…")
	}
	return strings.Join(lines, "\n")
}

const sudoersLast = "sudoers.last"

// Run polls until ctx ends. The first snapshot is stored silently (there is
// nothing to compare against); every later difference becomes an Event.
// save persists st after each change.
func (w *AccountsWatcher) Run(ctx context.Context, st *State, out chan<- Event, save func() error) {
	interval := w.Interval
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		w.tick(st, out, save, time.Now())
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}
	}
}

func (w *AccountsWatcher) tick(st *State, out chan<- Event, save func() error, now time.Time) {
	passwd, err := w.Passwd()
	if err != nil {
		return
	}
	sudoers, err := w.Sudoers()
	if err != nil {
		return
	}
	cur := Snapshot(passwd, w.HomeKeys, sudoers, now)
	if st.Accounts.Taken.IsZero() {
		st.Accounts = cur
		w.writeSudoersLast(sudoers)
		_ = save()
		return
	}
	var sudoDiff string
	if cur.Sudoers != st.Accounts.Sudoers {
		last, _ := os.ReadFile(filepath.Join(w.StateDir, sudoersLast))
		sudoDiff = SimpleDiff(string(last), string(sudoers), 10)
		w.writeSudoersLast(sudoers)
	}
	evs := Diff(st.Accounts, cur, sudoDiff, now)
	if len(evs) == 0 {
		return
	}
	st.Accounts = cur
	_ = save()
	for _, ev := range evs {
		out <- ev
	}
}

func (w *AccountsWatcher) writeSudoersLast(b []byte) {
	if w.StateDir == "" {
		return
	}
	_ = os.MkdirAll(w.StateDir, 0o700)
	_ = os.WriteFile(filepath.Join(w.StateDir, sudoersLast), b, 0o600)
}
