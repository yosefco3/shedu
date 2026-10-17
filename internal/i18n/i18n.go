// Package i18n holds every user-facing text of shedu, in Hebrew and English.
// Finding and alert IDs are the keys; texts are Go text/template strings whose
// placeholders ({{.count}}) are filled from Finding.Args.
package i18n

import (
	"bytes"
	"sort"
	"text/template"
)

// Lang selects a message set.
type Lang string

const (
	He Lang = "he"
	En Lang = "en"
)

// Msg is the rendered pair for one ID.
type Msg struct {
	Title   string // one line: what happened
	Explain string // one or two sentences: why it matters, what to do
}

var catalogs = map[Lang]map[string]Msg{He: he, En: en}

// Parse normalises a language code; anything unknown falls back to Hebrew.
func Parse(s string) Lang {
	if Lang(s) == En {
		return En
	}
	return He
}

// Get returns the raw (unrendered) message, falling back to English.
func Get(lang Lang, id string) (Msg, bool) {
	if m, ok := catalogs[lang][id]; ok {
		return m, true
	}
	m, ok := catalogs[En][id]
	return m, ok
}

// Render fills placeholders. Unknown IDs render as the ID itself so nothing
// is ever silently dropped from a report.
func Render(lang Lang, id string, args map[string]string) Msg {
	m, ok := Get(lang, id)
	if !ok {
		return Msg{Title: id}
	}
	return Msg{Title: fill(m.Title, args), Explain: fill(m.Explain, args)}
}

func fill(s string, args map[string]string) string {
	t, err := template.New("").Option("missingkey=zero").Parse(s)
	if err != nil {
		return s
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, args); err != nil {
		return s
	}
	return buf.String()
}

// IDs lists every message ID known in English (the reference catalog), sorted.
func IDs() []string {
	ids := make([]string, 0, len(en))
	for id := range en {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Word returns the one-word verdict for a 0–100 score.
func Word(lang Lang, score int) string {
	i := 3
	switch {
	case score >= 90:
		i = 0
	case score >= 70:
		i = 1
	case score >= 40:
		i = 2
	}
	return scoreWords[lang][i]
}

var scoreWords = map[Lang][4]string{
	He: {"מצוין", "סביר", "דורש טיפול", "מסוכן"},
	En: {"excellent", "fair", "needs attention", "dangerous"},
}

// UI holds short interface strings that are not finding messages.
var UI = map[Lang]map[string]string{
	He: {
		"score":     "ציון תקינות",
		"host":      "שרת",
		"more":      "ועוד {{.n}} ממצאים. לרשימה המלאה: sudo shedu check",
		"fix":       "תיקון",
		"nothing":   "לא נמצא שום דבר שדורש טיפול.",
		"connected": "🛡 Shedu מחובר לשרת {{.host}}.",
		"daily":     "📋 הדוח היומי של {{.host}}",
	},
	En: {
		"score":     "Health score",
		"host":      "server",
		"more":      "and {{.n}} more. Full list: sudo shedu check",
		"fix":       "fix",
		"nothing":   "Nothing needs your attention.",
		"connected": "🛡 Shedu is now watching {{.host}}.",
		"daily":     "📋 Daily report for {{.host}}",
	},
}

// T renders a UI string.
func T(lang Lang, key string, args map[string]string) string {
	s, ok := UI[lang][key]
	if !ok {
		s = UI[En][key]
	}
	return fill(s, args)
}
