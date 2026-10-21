package watch

import (
	"testing"
	"time"

	"github.com/yosefco3/shedu/internal/finding"
)

func TestAlertCloud(t *testing.T) {
	a := Alert{ID: "alert.bruteforce", Severity: finding.High, Key: "bruteforce:203.0.113.5",
		Args: map[string]string{"ip": "203.0.113.5", "count": "7", "users": "root"},
		Fix:  "sudo ufw deny from 203.0.113.5", Time: time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)}
	e1, e2 := a.Cloud(), a.Cloud()
	if e1.UID == "" || e1.UID != e2.UID || len(e1.UID) != 32 {
		t.Fatalf("UID must be stable: %q %q", e1.UID, e2.UID)
	}
	if e1.Severity != "high" || e1.Fix != a.Fix || e1.Text["he"].Title == "" || e1.Text["en"].Title == "" {
		t.Errorf("event: %+v", e1)
	}
	b := a
	b.Time = b.Time.Add(time.Second)
	c := a
	c.Args = map[string]string{"ip": "203.0.113.6", "count": "7", "users": "root"}
	if b.UID() == a.UID() || c.UID() == a.UID() {
		t.Error("different alerts must get different UIDs")
	}
}
