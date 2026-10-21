package finding

import (
	"github.com/yosefco3/shedu/internal/i18n"
	"github.com/yosefco3/shedu/pkg/cloudapi"
)

// Cloud converts a report to the public cloud schema: the same findings as `check --json`
// (worst first, at most cloudapi.MaxFindings), rendered in Hebrew and English, plus the
// ports reachable from outside.
func Cloud(r Report, agentVersion string) cloudapi.Report {
	sorted := r.Sorted()
	if len(sorted) > cloudapi.MaxFindings {
		sorted = sorted[:cloudapi.MaxFindings]
	}
	out := cloudapi.Report{
		Host: r.Host, Time: r.Time.UTC(), Score: r.Score(), AgentVersion: agentVersion,
		Findings:  make([]cloudapi.Finding, 0, len(sorted)),
		Listeners: make([]cloudapi.Listener, 0, len(r.Listeners)),
	}
	for _, f := range sorted {
		out.Findings = append(out.Findings, cloudapi.Finding{
			ID: f.ID, Severity: f.Severity.String(), Args: f.Args, Fix: f.Fix, Evidence: f.Evidence,
			Text: Texts(f.ID, f.Args),
		})
	}
	for _, l := range r.Listeners {
		out.Listeners = append(out.Listeners, cloudapi.Listener{Port: l.Port, Proto: l.Proto, Bind: l.Bind, Process: l.Process})
	}
	return out
}

// Texts renders one message ID in every language the agent ships.
func Texts(id string, args map[string]string) map[string]cloudapi.Text {
	out := make(map[string]cloudapi.Text, 2)
	for _, l := range []i18n.Lang{i18n.He, i18n.En} {
		m := i18n.Render(l, id, args)
		out[string(l)] = cloudapi.Text{Title: m.Title, Explain: m.Explain}
	}
	return out
}
