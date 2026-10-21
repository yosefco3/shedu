// Package finding defines the shared data model of shedu: a Finding is one thing
// the server owner should know about, and a Report is a scored collection of them.
package finding

import (
	"sort"
	"time"
)

// Severity orders findings from "nice to know" to "act now".
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var severityNames = [...]string{"info", "low", "medium", "high", "critical"}

// String returns the lowercase name used in JSON and in message keys.
func (s Severity) String() string {
	if s < Info || int(s) >= len(severityNames) {
		return "unknown"
	}
	return severityNames[s]
}

// Finding is one observation about the host. ID is both a stable identifier and
// the i18n key for its title and explanation; Args fill placeholders in those texts.
type Finding struct {
	ID       string            `json:"id"`
	Severity Severity          `json:"severity"`
	Args     map[string]string `json:"args,omitempty"`
	Fix      string            `json:"fix,omitempty"`      // copy-pasteable shell command, "" if none
	Evidence string            `json:"evidence,omitempty"` // raw line(s) that triggered it
}

// Report is the result of one full check run.
type Report struct {
	Host     string    `json:"host"`
	Time     time.Time `json:"time"`
	Findings []Finding `json:"findings"`
	// Listeners are the TCP ports reachable from outside (what ports.summary lists). They
	// go to the cloud report only; `check --json` keeps its documented shape.
	Listeners []Listener `json:"-"`
}

// Listener is one TCP port reachable from outside the host.
type Listener struct {
	Port    int
	Proto   string // tcp | tcp6
	Bind    string // listening address, e.g. 0.0.0.0
	Process string // comm, "" if unknown
}

// penalty is subtracted from 100 per finding; the score never drops below 0.
var penalty = map[Severity]int{Info: 0, Low: 3, Medium: 8, High: 15, Critical: 30}

// Score returns 0–100: 100 means nothing to report.
func (r Report) Score() int {
	score := 100
	for _, f := range r.Findings {
		score -= penalty[f.Severity]
	}
	if score < 0 {
		return 0
	}
	return score
}

// Sorted returns a copy of the findings ordered by severity (worst first), then by ID.
func (r Report) Sorted() []Finding {
	out := make([]Finding, len(r.Findings))
	copy(out, r.Findings)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		return out[i].ID < out[j].ID
	})
	return out
}
