package watch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yosefco3/shedu/internal/finding"
	"github.com/yosefco3/shedu/internal/i18n"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) add(d time.Duration)     { c.t = c.t.Add(d) }
func newRules(c *clock) (*Rules, *State) { r := NewRules(5); r.Clock = c.now; return r, newState() }

func fail(ip, user string) Event { return Event{Kind: LoginFail, IP: ip, User: user} }
func login(ip, user string) Event {
	return Event{Kind: LoginOK, IP: ip, User: user, Method: "publickey"}
}

func TestBruteForceThresholdAndCooldown(t *testing.T) {
	c := &clock{time.Date(2026, 10, 17, 3, 0, 0, 0, time.UTC)}
	r, st := newRules(c)
	for i := 0; i < 4; i++ {
		if _, ok := r.Feed(fail("1.2.3.4", "root"), st); ok {
			t.Fatalf("alert after %d failures", i+1)
		}
		c.add(time.Second)
	}
	a, ok := r.Feed(fail("1.2.3.4", "admin"), st)
	if !ok || a.ID != "alert.bruteforce" || a.Severity != finding.High || a.Args["count"] != "5" || a.Args["users"] != "root, admin" {
		t.Fatalf("5th failure must alert: %+v %v", a, ok)
	}
	if _, ok := r.Feed(fail("1.2.3.4", "root"), st); ok {
		t.Error("6th failure within cooldown must not alert again")
	}
	c.add(61 * time.Minute)
	for i := 0; i < 5; i++ {
		c.add(time.Second)
		a, ok = r.Feed(fail("1.2.3.4", "root"), st)
	}
	if !ok || a.Args["count"] != "5" {
		t.Errorf("after cooldown a fresh burst must alert with only recent failures counted: %+v %v", a, ok)
	}
}

func TestBruteForceWindow(t *testing.T) {
	c := &clock{time.Unix(1_700_000_000, 0)}
	r, st := newRules(c)
	for i := 0; i < 4; i++ {
		r.Feed(fail("9.9.9.9", "x"), st)
	}
	c.add(11 * time.Minute)
	if _, ok := r.Feed(fail("9.9.9.9", "x"), st); ok {
		t.Error("old failures outside the window must not count")
	}
}

func TestNewIPLogin(t *testing.T) {
	c := &clock{time.Unix(1_700_000_000, 0)}
	r, st := newRules(c)
	if _, ok := r.Feed(login("10.0.0.5", "yosef"), st); ok {
		t.Error("first login after install is learned silently")
	}
	if _, ok := r.Feed(login("10.0.0.5", "yosef"), st); ok {
		t.Error("known IP must not alert")
	}
	a, ok := r.Feed(login("203.0.113.9", "yosef"), st)
	if !ok || a.ID != "alert.login_new_ip" || a.Severity != finding.Medium || a.Args["private"] != "" {
		t.Errorf("new public IP must alert: %+v %v", a, ok)
	}
	if _, ok := r.Feed(login("203.0.113.9", "yosef"), st); ok {
		t.Error("the new IP is now known")
	}
	a, _ = r.Feed(login("192.168.1.7", "yosef"), st)
	if a.Args["private"] != "1" {
		t.Errorf("private IP must be flagged: %+v", a)
	}
	if _, ok := r.Feed(login("127.0.0.1", "yosef"), st); ok {
		t.Error("loopback never alerts")
	}
	if _, ok := r.Feed(login("::1", "yosef"), st); ok {
		t.Error("ipv6 loopback never alerts")
	}
}

func TestLoginAfterBruteForceWins(t *testing.T) {
	c := &clock{time.Unix(1_700_000_000, 0)}
	r, st := newRules(c)
	r.Feed(login("10.0.0.5", "yosef"), st) // learn one IP so new-IP logic is active
	for i := 0; i < 5; i++ {
		r.Feed(fail("5.5.5.5", "root"), st)
	}
	a, ok := r.Feed(login("5.5.5.5", "root"), st)
	if !ok || a.ID != "alert.login_after_bruteforce" || a.Severity != finding.Critical {
		t.Errorf("successful login after a burst must be critical, got %+v %v", a, ok)
	}
}

func TestSudoRules(t *testing.T) {
	c := &clock{time.Unix(1_700_000_000, 0)}
	r, st := newRules(c)
	if _, ok := r.Feed(Event{Kind: SudoCmd, User: "yosef", Detail: "/usr/bin/apt"}, st); ok {
		t.Error("first sudo user is learned silently")
	}
	if _, ok := r.Feed(Event{Kind: SudoCmd, User: "yosef"}, st); ok {
		t.Error("known sudo user")
	}
	a, ok := r.Feed(Event{Kind: SudoCmd, User: "bob", Detail: "/bin/cat /etc/shadow"}, st)
	if !ok || a.ID != "alert.sudo_new_user" || a.Args["command"] != "/bin/cat /etc/shadow" {
		t.Errorf("new sudo user must alert: %+v", a)
	}
	a, ok = r.Feed(Event{Kind: SudoFail, User: "bob", Detail: "user NOT in sudoers"}, st)
	if !ok || a.ID != "alert.sudo_fail" {
		t.Errorf("sudo fail: %+v", a)
	}
	if _, ok := r.Feed(Event{Kind: SudoFail, User: "bob"}, st); ok {
		t.Error("sudo fail is rate limited per user")
	}
}

func TestAccountEventsAreDirect(t *testing.T) {
	r, st := newRules(&clock{time.Unix(1_700_000_000, 0)})
	for i := 0; i < 2; i++ {
		a, ok := r.Feed(Event{Kind: UserAdded, User: "guardtest", Detail: "1001"}, st)
		if !ok || a.ID != "alert.user_added" || a.Severity != finding.High || !strings.Contains(a.Fix, "userdel -r guardtest") {
			t.Errorf("user_added #%d: %+v %v", i, a, ok)
		}
	}
	a, _ := r.Feed(Event{Kind: KeyAdded, User: "root", Detail: "SHA256:abc yosef@laptop"}, st)
	if a.Args["fp"] != "SHA256:abc" || a.Args["comment"] != "yosef@laptop" || a.Fix != "sudo nano /root/.ssh/authorized_keys" {
		t.Errorf("key_added: %+v", a)
	}
	msg := a.Telegram(i18n.He)
	if !strings.Contains(msg, "<b>") || !strings.Contains(msg, "SHA256:abc") || !strings.Contains(msg, "<code>sudo nano") {
		t.Errorf("telegram render: %s", msg)
	}
}

func TestStateSaveLoad(t *testing.T) {
	dir := t.TempDir()
	st := newState()
	st.KnownIPs["1.1.1.1"] = time.Unix(1_700_000_000, 0).UTC()
	st.LastAlerts["k"] = time.Unix(1_700_000_100, 0).UTC()
	if err := st.Save(dir); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(filepath.Join(dir, "state.json"))
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", info.Mode())
	}
	got, err := LoadState(dir)
	if err != nil || !got.KnownIPs["1.1.1.1"].Equal(st.KnownIPs["1.1.1.1"]) || !got.LastAlerts["k"].Equal(st.LastAlerts["k"]) {
		t.Errorf("round trip: %+v %v", got, err)
	}
	if got.Fresh() {
		t.Error("state with a known IP is not fresh")
	}
	empty, err := LoadState(filepath.Join(dir, "nope"))
	if err != nil || !empty.Fresh() {
		t.Errorf("missing dir must give a fresh state: %v", err)
	}
	os.WriteFile(filepath.Join(dir, "state.json"), []byte("{not json"), 0o600)
	bad, err := LoadState(dir)
	if err == nil || !bad.Fresh() {
		t.Errorf("corrupt state must be reported and replaced: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "state.json.bad")); err != nil {
		t.Error("corrupt file must be moved to .bad")
	}
}
