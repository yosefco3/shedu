package finding

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/yosefco12/shedu/internal/i18n"
)

// Rendered is a Finding with its texts resolved for one language.
type Rendered struct {
	ID       string   `json:"id"`
	Severity Severity `json:"severity"`
	Title    string   `json:"title"`
	Explain  string   `json:"explain"`
	Fix      string   `json:"fix,omitempty"`
}

var icons = map[Severity]string{Info: "🔵", Low: "🟡", Medium: "🟠", High: "🔴", Critical: "🚨"}

// Icon returns the emoji used for a severity in every channel.
func Icon(s Severity) string { return icons[s] }

// RenderReport resolves every finding, worst first.
func RenderReport(r Report, lang i18n.Lang) []Rendered {
	out := make([]Rendered, 0, len(r.Findings))
	for _, f := range r.Sorted() {
		m := i18n.Render(lang, f.ID, f.Args)
		out = append(out, Rendered{ID: f.ID, Severity: f.Severity, Title: m.Title, Explain: m.Explain, Fix: f.Fix})
	}
	return out
}

// Text renders the terminal report.
func Text(r Report, lang i18n.Lang) string {
	var b strings.Builder
	score := r.Score()
	fmt.Fprintf(&b, "%s: %d/100 (%s) — %s\n", i18n.T(lang, "score", nil), score, i18n.Word(lang, score), r.Host)
	items := RenderReport(r, lang)
	if len(items) == 0 {
		b.WriteString(i18n.T(lang, "nothing", nil) + "\n")
		return b.String()
	}
	for _, it := range items {
		fmt.Fprintf(&b, "\n%s %s\n", icons[it.Severity], it.Title)
		if it.Explain != "" {
			fmt.Fprintf(&b, "   %s\n", it.Explain)
		}
		if it.Fix != "" {
			fmt.Fprintf(&b, "   $ %s\n", it.Fix)
		}
	}
	return b.String()
}

// Telegram renders an HTML-mode message with at most max findings.
// Fix commands are shown in <code> so they can be copied with one tap.
func Telegram(r Report, lang i18n.Lang, max int) string {
	var b strings.Builder
	score := r.Score()
	fmt.Fprintf(&b, "<b>%s: %d/100</b> (%s)\n%s: %s\n", i18n.T(lang, "score", nil), score, i18n.Word(lang, score), i18n.T(lang, "host", nil), esc(r.Host))
	items := RenderReport(r, lang)
	if len(items) == 0 {
		b.WriteString("\n" + i18n.T(lang, "nothing", nil))
		return b.String()
	}
	shown := items
	if max > 0 && len(shown) > max {
		shown = shown[:max]
	}
	for _, it := range shown {
		fmt.Fprintf(&b, "\n%s <b>%s</b>\n%s\n", icons[it.Severity], esc(it.Title), esc(it.Explain))
		if it.Fix != "" {
			fmt.Fprintf(&b, "<code>%s</code>\n", esc(it.Fix))
		}
	}
	if rest := len(items) - len(shown); rest > 0 {
		b.WriteString("\n" + i18n.T(lang, "more", map[string]string{"n": strconv.Itoa(rest)}))
	}
	return b.String()
}

// JSON is the machine-readable report: stable field names for the dashboard.
func JSON(r Report) ([]byte, error) {
	type doc struct {
		Host     string    `json:"host"`
		Time     string    `json:"time"`
		Score    int       `json:"score"`
		Findings []Finding `json:"findings"`
	}
	return json.MarshalIndent(doc{Host: r.Host, Time: r.Time.UTC().Format("2006-01-02T15:04:05Z"), Score: r.Score(), Findings: r.Sorted()}, "", "  ")
}

// esc makes a string safe for Telegram HTML parse mode.
func esc(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}
