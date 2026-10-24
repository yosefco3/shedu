package i18n

import (
	"regexp"
	"strings"
	"testing"
)

// Every ID must exist in both languages, with no empty texts and matching placeholders.
func TestCatalogsComplete(t *testing.T) {
	for _, id := range IDs() {
		h, ok := he[id]
		if !ok {
			t.Errorf("%s: missing Hebrew", id)
			continue
		}
		e := en[id]
		if h.Title == "" || h.Explain == "" || e.Title == "" || e.Explain == "" {
			t.Errorf("%s: empty text", id)
		}
		hebrew := placeholders(h.Title + h.Explain)
		for ph := range placeholders(e.Title + e.Explain) {
			if !hebrew[ph] {
				t.Errorf("%s: Hebrew lacks placeholder %s", id, ph)
			}
		}
	}
	for id := range he {
		if _, ok := en[id]; !ok {
			t.Errorf("%s: Hebrew-only message", id)
		}
	}
	for lang, m := range UI {
		for k := range UI[En] {
			if m[k] == "" {
				t.Errorf("UI[%s][%s] missing", lang, k)
			}
		}
	}
}

var fieldRef = regexp.MustCompile(`\.[A-Za-z_]+`)
var quoted = regexp.MustCompile(`\\?"(?:[^"\\]|\\.)*?\\?"`)

// placeholders returns the data fields a text refers to ({{.count}}, {{if .lan}},
// {{plural .count "a" "b"}} all give their .field), ignoring quoted plural forms.
func placeholders(s string) map[string]bool {
	out := map[string]bool{}
	for _, part := range strings.Split(s, "{{")[1:] {
		i := strings.Index(part, "}}")
		if i < 0 {
			continue
		}
		action := quoted.ReplaceAllString(part[:i], "")
		for _, f := range fieldRef.FindAllString(action, -1) {
			out[f] = true
		}
	}
	return out
}

func TestRender(t *testing.T) {
	m := Render(He, "updates.security_pending", map[string]string{"security": "12", "names": "openssl, curl"})
	if !strings.HasPrefix(m.Title, "12 ") || !strings.Contains(m.Explain, "openssl, curl") {
		t.Errorf("placeholders not filled: %+v", m)
	}
	if m := Render(En, "no.such.id", nil); m.Title != "no.such.id" || m.Explain != "" {
		t.Errorf("unknown id must render as itself, got %+v", m)
	}
	if m := Render(He, "ports.summary", nil); strings.Contains(m.Title, "<no value>") {
		t.Errorf("missing args must render empty, not <no value>: %q", m.Title)
	}
}

func TestWordAndParse(t *testing.T) {
	cases := map[int]string{100: "excellent", 90: "excellent", 89: "fair", 70: "fair", 69: "needs attention", 40: "needs attention", 39: "dangerous", 0: "dangerous"}
	for score, want := range cases {
		if got := Word(En, score); got != want {
			t.Errorf("Word(%d) = %q, want %q", score, got, want)
		}
	}
	if Word(He, 95) != "מצוין" {
		t.Error("Hebrew word")
	}
	if Parse("en") != En || Parse("he") != He || Parse("fr") != He || Parse("") != He {
		t.Error("Parse fallback")
	}
	if T(He, "more", map[string]string{"n": "4"}) != "ועוד 4 ממצאים. לרשימה המלאה: sudo shedu check" {
		t.Errorf("T = %q", T(He, "more", map[string]string{"n": "4"}))
	}
}

func TestPlural(t *testing.T) {
	cases := []struct{ count, want string }{
		{"1", "1 key"}, {"0", "0 keys"}, {"2", "2 keys"}, {"3", "3 keys"}, {"", " keys"}, {"x", "x keys"}, {"10", "10 keys"},
	}
	for _, c := range cases {
		if got := plural(c.count, "1 key", "%s keys"); got != c.want {
			t.Errorf("plural(%q) = %q, want %q", c.count, got, c.want)
		}
	}
	if got := plural("1", "it", "them"); got != "it" {
		t.Errorf("form without %%s: %q", got)
	}
}

// Messages that put a number next to a noun must be grammatical for 1 and for many.
func TestPluralMessages(t *testing.T) {
	type tc struct {
		lang        Lang
		id, key, n  string
		wantTitle   string
		wantExplain string // substring; empty to skip
	}
	cases := []tc{
		{En, "keys.inventory", "count", "1", "1 SSH key can log in to this server", "Whoever holds this key"},
		{En, "keys.inventory", "count", "3", "3 SSH keys can log in to this server", "Whoever holds one of these keys"},
		{He, "keys.inventory", "count", "1", "מפתח SSH אחד יכול להיכנס לשרת הזה", "מי שמחזיק את המפתח הזה"},
		{He, "keys.inventory", "count", "3", "3 מפתחות SSH יכולים להיכנס לשרת הזה", "מי שמחזיק אחד מהמפתחות האלה"},
		{En, "ports.summary", "count", "1", "1 port reachable from the internet: L", ""},
		{En, "ports.summary", "count", "3", "3 ports reachable from the internet: L", ""},
		{He, "ports.summary", "count", "1", "פורט אחד נגיש מהאינטרנט: L", ""},
		{He, "ports.summary", "count", "3", "3 פורטים נגישים מהאינטרנט: L", ""},
		{En, "keys.anonymous", "count", "1", "1 SSH key has no name", ""},
		{En, "keys.anonymous", "count", "3", "3 SSH keys have no name", ""},
		{He, "keys.anonymous", "count", "1", "למפתח SSH אחד אין שם", ""},
		{He, "keys.anonymous", "count", "3", "ל-3 מפתחות SSH אין שם", ""},
		{En, "updates.pending", "count", "1", "1 update is waiting", "It is not a security fix, but"},
		{En, "updates.pending", "count", "3", "3 updates are waiting", "No security fixes among them, but"},
		{He, "updates.pending", "count", "1", "עדכון אחד מחכה להתקנה", "זה לא תיקון אבטחה"},
		{He, "updates.pending", "count", "3", "3 עדכונים מחכים להתקנה", "אין ביניהם תיקוני אבטחה"},
		{En, "updates.security_pending", "security", "1", "1 security update is waiting", "This fixes a hole that is already public, so attackers know about it too."},
		{En, "updates.security_pending", "security", "3", "3 security updates are waiting", "These fix holes that are already public"},
		{He, "updates.security_pending", "security", "1", "עדכון אבטחה אחד מחכה להתקנה", "זה חור שכבר פורסם, ולכן גם התוקפים מכירים אותו."},
		{He, "updates.security_pending", "security", "3", "3 עדכוני אבטחה מחכים להתקנה", "אלה חורים שכבר פורסמו"},
		{En, "perms.world_writable_etc", "count", "1", "1 system config file is writable by everyone", "can change it: P."},
		{En, "perms.world_writable_etc", "count", "3", "3 system config files are writable by everyone", "can change them: P."},
		{He, "perms.world_writable_etc", "count", "1", "קובץ הגדרות אחד של המערכת ניתן לכתיבה על ידי כולם", "יכול לשנות אותו: P."},
		{He, "perms.world_writable_etc", "count", "3", "3 קובצי הגדרות של המערכת ניתנים לכתיבה על ידי כולם", "יכול לשנות אותם: P."},
		{En, "secrets.webroot_backup", "count", "1", "1 backup or archive file sits in a web folder", ""},
		{En, "secrets.webroot_backup", "count", "3", "3 backup or archive files sit in a web folder", ""},
		{He, "secrets.webroot_backup", "count", "1", "קובץ גיבוי או ארכיון אחד נמצא בתיקיית האתר", ""},
		{He, "secrets.webroot_backup", "count", "3", "3 קבצי גיבוי או ארכיון נמצאים בתיקיית האתר", ""},
		{En, "secrets.key_open", "count", "1", "1 private key can be read by others", ""},
		{En, "secrets.key_open", "count", "3", "3 private keys can be read by others", ""},
		{He, "secrets.key_open", "count", "1", "מפתח פרטי אחד פתוח לקריאה של אחרים", ""},
		{He, "secrets.key_open", "count", "3", "3 מפתחות פרטיים פתוחים לקריאה של אחרים", ""},
		{En, "alert.clamav", "count", "1", "🦠 ClamAV found 1 infected file", "the fix moves it to"},
		{En, "alert.clamav", "count", "3", "🦠 ClamAV found 3 infected files", "the fix moves them to"},
		{He, "alert.clamav", "count", "1", "🦠 ClamAV מצא קובץ נגוע אחד", "מעבירה אותו לתיקייה"},
		{He, "alert.clamav", "count", "3", "🦠 ClamAV מצא 3 קבצים נגועים", "מעבירה אותם לתיקייה"},
		{En, "alert.outbound_beacon", "count", "1", "Possible beacon: c calls 1.2.3.4:80 every 5m", "1 connection at a machine-regular rhythm."},
		{En, "alert.outbound_beacon", "count", "6", "Possible beacon: c calls 1.2.3.4:80 every 5m", "6 connections at a machine-regular rhythm."},
		{He, "alert.outbound_beacon", "count", "1", "ייתכן שזה איתות: c מתקשר אל 1.2.3.4:80 כל 5m", "חיבור אחד בקצב קבוע"},
		{He, "alert.outbound_beacon", "count", "6", "ייתכן שזה איתות: c מתקשר אל 1.2.3.4:80 כל 5m", "6 חיבורים בקצב קבוע"},
	}
	for _, c := range cases {
		args := map[string]string{c.key: c.n, "list": "L", "paths": "P", "names": "N", "comm": "c", "ip": "1.2.3.4", "port": "80", "every": "5m"}
		m := Render(c.lang, c.id, args)
		if m.Title != c.wantTitle {
			t.Errorf("%s/%s n=%s title = %q, want %q", c.lang, c.id, c.n, m.Title, c.wantTitle)
		}
		if c.wantExplain != "" && !strings.Contains(m.Explain, c.wantExplain) {
			t.Errorf("%s/%s n=%s explain = %q, want it to contain %q", c.lang, c.id, c.n, m.Explain, c.wantExplain)
		}
	}
}

// Two numbers in one message, each with its own form.
func TestPluralTwoNumbers(t *testing.T) {
	bf := func(lang Lang, count, minutes string) string {
		return Render(lang, "alert.bruteforce", map[string]string{"count": count, "ip": "1.2.3.4", "minutes": minutes}).Title
	}
	for _, c := range []struct {
		lang           Lang
		count, minutes string
		want           string
	}{
		{En, "1", "1", "🚨 Break-in attempt: 1 failed login from 1.2.3.4 in the last minute"},
		{En, "5", "10", "🚨 Break-in attempt: 5 failed logins from 1.2.3.4 in the last 10 minutes"},
		{He, "1", "1", "🚨 ניסיון פריצה: ניסיון כניסה כושל אחד מ-1.2.3.4 בדקה האחרונה"},
		{He, "5", "10", "🚨 ניסיון פריצה: 5 ניסיונות כניסה כושלים מ-1.2.3.4 ב-10 הדקות האחרונות"},
	} {
		if got := bf(c.lang, c.count, c.minutes); got != c.want {
			t.Errorf("%s bruteforce %s/%s = %q, want %q", c.lang, c.count, c.minutes, got, c.want)
		}
	}
	mf := func(lang Lang, count, secs string) string {
		return Render(lang, "alert.massfile", map[string]string{"count": count, "dir": "/var/www", "seconds": secs}).Title
	}
	for _, c := range []struct {
		lang        Lang
		count, secs string
		want        string
	}{
		{En, "1", "1", "📁 1 file changed in /var/www within 1 second"},
		{En, "50", "10", "📁 50 files changed in /var/www within 10 seconds"},
		{He, "1", "1", "📁 קובץ אחד השתנה ב-/var/www תוך שנייה אחת"},
		{He, "50", "10", "📁 50 קבצים השתנו ב-/var/www תוך 10 שניות"},
	} {
		if got := mf(c.lang, c.count, c.secs); got != c.want {
			t.Errorf("%s massfile %s/%s = %q, want %q", c.lang, c.count, c.secs, got, c.want)
		}
	}
}

func TestUIMorePlural(t *testing.T) {
	for _, c := range []struct {
		lang Lang
		n    string
		want string
	}{
		{He, "1", "ועוד ממצא אחד. לרשימה המלאה: sudo shedu check"},
		{He, "4", "ועוד 4 ממצאים. לרשימה המלאה: sudo shedu check"},
		{En, "1", "and 1 more. Full list: sudo shedu check"},
		{En, "4", "and 4 more. Full list: sudo shedu check"},
	} {
		if got := T(c.lang, "more", map[string]string{"n": c.n}); got != c.want {
			t.Errorf("more %s/%s = %q, want %q", c.lang, c.n, got, c.want)
		}
	}
}
