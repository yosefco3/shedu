package finding

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCloudReportMatchesCheckJSON(t *testing.T) {
	r := Report{Host: "web-1", Time: time.Date(2026, 10, 21, 8, 0, 0, 0, time.FixedZone("IDT", 3*3600)),
		Findings: []Finding{
			{ID: "ports.summary", Severity: Info, Args: map[string]string{"count": "1", "list": "22 sshd"}},
			{ID: "ssh.root_login", Severity: High, Fix: "sudo sed -i x /etc/ssh/sshd_config", Evidence: "PermitRootLogin yes"},
		},
		Listeners: []Listener{{Port: 22, Proto: "tcp", Bind: "0.0.0.0", Process: "sshd"}},
	}
	c := Cloud(r, "v0.3.0")
	if c.Score != r.Score() || c.AgentVersion != "v0.3.0" || c.Time.Location() != time.UTC || len(c.Findings) != 2 {
		t.Fatalf("report: %+v", c)
	}
	if c.Findings[0].ID != "ssh.root_login" || c.Findings[0].Severity != "high" || c.Findings[0].Evidence != "PermitRootLogin yes" {
		t.Errorf("worst first, fields kept: %+v", c.Findings[0])
	}
	for _, f := range c.Findings {
		if f.Text["he"].Title == "" || f.Text["en"].Title == "" || f.Text["he"].Title == f.Text["en"].Title {
			t.Errorf("%s: both languages expected: %+v", f.ID, f.Text)
		}
	}
	if len(c.Listeners) != 1 || c.Listeners[0].Bind != "0.0.0.0" {
		t.Errorf("listeners: %+v", c.Listeners)
	}
	// check --json keeps its shape: no listeners there
	b, _ := JSON(r)
	if strings.Contains(string(b), "listeners") || strings.Contains(string(b), "sshd\"") && strings.Contains(string(b), "\"bind\"") {
		t.Errorf("check --json changed: %s", b)
	}
	var doc map[string]any
	json.Unmarshal(b, &doc) //nolint:errcheck
	if len(doc) != 4 {
		t.Errorf("check --json keys: %v", doc)
	}
}
