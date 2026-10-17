package watch

import (
	"bufio"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseAuthLines(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "auth_lines.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	now := time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC)
	type want struct {
		kind                 Kind
		user, ip, method, dt string
	}
	wants := []want{
		{LoginFail, "root", "185.220.101.7", "", ""},
		{LoginFail, "admin", "45.83.64.11", "", ""},
		{InvalidUser, "oracle", "103.145.13.90", "", ""},
		{LoginOK, "yosef", "10.0.0.5", "publickey", ""},
		{LoginOK, "deploy", "91.108.4.30", "password", ""},
		{SudoCmd, "yosef", "", "", "/usr/bin/apt update"},
		{SudoFail, "yosef", "", "", "3 incorrect password attempts"},
		{SudoFail, "bob", "", "", "user NOT in sudoers"},
		{LoginOK, "alice", "2001:db8::7", "keyboard-interactive", ""},
		{LoginFail, "root", "203.0.113.9", "", ""},
	}
	var got []Event
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if ev, ok := ParseAuthLine(sc.Text(), now); ok {
			got = append(got, ev)
		}
	}
	if len(got) != len(wants) {
		t.Fatalf("got %d events, want %d:\n%+v", len(got), len(wants), got)
	}
	for i, w := range wants {
		g := got[i]
		if g.Kind != w.kind || g.User != w.user || g.IP != w.ip || g.Method != w.method || (w.dt != "" && g.Detail != w.dt) {
			t.Errorf("event %d = %+v, want %+v", i, g, w)
		}
	}
	// syslog timestamp takes the year from `now`; ISO timestamp is used as-is
	if got[0].Time.Year() != 2026 || got[0].Time.Month() != 3 || got[0].Time.Hour() != 3 {
		t.Errorf("syslog ts = %v", got[0].Time)
	}
	if !got[8].Time.Equal(time.Date(2026, 10, 17, 3, 16, 0, 0, time.UTC)) {
		t.Errorf("iso ts = %v", got[8].Time)
	}
}

func TestParseAuthLineYearRollover(t *testing.T) {
	now := time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC)
	ev, ok := ParseAuthLine("Dec 31 23:59:00 h sshd[1]: Invalid user x from 1.2.3.4 port 1", now)
	if !ok || ev.Time.Year() != 2026 {
		t.Errorf("December line read in January must be last year: %v", ev.Time)
	}
}

func TestParseJournalLines(t *testing.T) {
	f, _ := os.Open(filepath.Join("testdata", "journal_lines.jsonl"))
	defer f.Close()
	var got []Event
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if ev, ok := ParseJournalLine(sc.Bytes()); ok {
			got = append(got, ev)
		}
	}
	if len(got) != 3 {
		t.Fatalf("want 3 events (cron, binary and noise skipped), got %d: %+v", len(got), got)
	}
	if got[0].Kind != LoginFail || !got[0].Time.Equal(time.UnixMicro(1760678042123456)) {
		t.Errorf("first = %+v", got[0])
	}
	if got[1].Kind != LoginOK || got[1].Method != "publickey" {
		t.Errorf("second = %+v", got[1])
	}
	if got[2].Kind != SudoCmd || got[2].Detail != "/usr/bin/systemctl restart nginx" {
		t.Errorf("third = %+v", got[2])
	}
}
