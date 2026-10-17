package finding

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yosefco12/shedu/internal/i18n"
)

func sample() Report {
	return Report{Host: "web-1", Time: time.Date(2026, 10, 17, 8, 0, 0, 0, time.UTC), Findings: []Finding{
		{ID: "updates.no_auto", Severity: Medium, Fix: "sudo apt install -y unattended-upgrades"},
		{ID: "ports.summary", Severity: Info, Args: map[string]string{"count": "2", "list": "22 sshd, 80 nginx"}},
		{ID: "ssh.password_auth", Severity: High, Fix: "echo 'PasswordAuthentication no' | sudo tee -a /etc/ssh/sshd_config.d/00-shedu.conf && sudo sshd -t && sudo systemctl reload ssh"},
		{ID: "ports.db_public", Severity: Critical, Args: map[string]string{"service": "redis", "port": "6379", "process": "redis-server"}, Fix: "sudo ufw deny 6379/tcp"},
	}}
}

func TestTextGolden(t *testing.T) {
	got := Text(sample(), i18n.He)
	want, err := os.ReadFile(filepath.Join("testdata", "report_he.golden.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("golden mismatch.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestTextOrderAndScore(t *testing.T) {
	out := Text(sample(), i18n.En)
	if !strings.HasPrefix(out, "Health score: 47/100 (needs attention) — web-1") {
		t.Errorf("header = %q", strings.SplitN(out, "\n", 2)[0])
	}
	redis, pw, auto, sum := strings.Index(out, "redis"), strings.Index(out, "password"), strings.Index(out, "automatically"), strings.Index(out, "reachable")
	if !(redis < pw && pw < auto && auto < sum) {
		t.Errorf("findings must be ordered worst first: %d %d %d %d", redis, pw, auto, sum)
	}
	empty := Text(Report{Host: "h"}, i18n.En)
	if !strings.Contains(empty, "100/100 (excellent)") || !strings.Contains(empty, "Nothing needs") {
		t.Errorf("empty report = %q", empty)
	}
}

func TestTelegram(t *testing.T) {
	msg := Telegram(sample(), i18n.He, 2)
	if strings.Count(msg, "<b>") != 3 { // header + 2 findings
		t.Errorf("want header + 2 findings in bold, got:\n%s", msg)
	}
	if !strings.Contains(msg, "ועוד 2 ממצאים") {
		t.Errorf("missing 'and N more' line:\n%s", msg)
	}
	if !strings.Contains(msg, "<code>sudo ufw deny 6379/tcp</code>") {
		t.Errorf("fix must be in <code>:\n%s", msg)
	}
	r := Report{Host: "a<b>&c", Findings: []Finding{{ID: "x", Severity: Low, Fix: "echo '<x>'"}}}
	if m := Telegram(r, i18n.En, 0); strings.Contains(m, "a<b>") || !strings.Contains(m, "&lt;x&gt;") {
		t.Errorf("HTML must be escaped: %s", m)
	}
}

func TestJSONRoundTrip(t *testing.T) {
	b, err := JSON(sample())
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Host     string    `json:"host"`
		Time     string    `json:"time"`
		Score    int       `json:"score"`
		Findings []Finding `json:"findings"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Score != 47 || doc.Time != "2026-10-17T08:00:00Z" || len(doc.Findings) != 4 || doc.Findings[0].ID != "ports.db_public" {
		t.Errorf("round trip: %+v", doc)
	}
}
