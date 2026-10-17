package i18n

import (
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
		for _, ph := range placeholders(e.Title + e.Explain) {
			if !strings.Contains(h.Title+h.Explain, ph) {
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

func placeholders(s string) []string {
	var out []string
	for _, part := range strings.Split(s, "{{")[1:] {
		if i := strings.Index(part, "}}"); i >= 0 {
			out = append(out, "{{"+part[:i]+"}}")
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
