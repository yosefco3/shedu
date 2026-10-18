package watch

import (
	"fmt"
	"testing"
	"testing/fstest"
	"time"

	"github.com/yosefco3/shedu/internal/config"
)

func TestSuspiciousLineage(t *testing.T) {
	procs := []Process{
		{PID: 1, Comm: "systemd"},
		{PID: 10, PPID: 1, Comm: "php-fpm8.1"},
		{PID: 11, PPID: 10, Comm: "bash", Cmdline: []string{"bash", "-i"}},                      // webshell
		{PID: 12, PPID: 11, Comm: "bash"},                                                       // nested: same break-in
		{PID: 13, PPID: 10, Comm: "sh", Cmdline: []string{"sh", "-c", "/usr/sbin/sendmail -t"}}, // php mail()
		{PID: 20, PPID: 1, Comm: "sshd"},
		{PID: 21, PPID: 20, Comm: "bash"}, // a normal login
		{PID: 30, PPID: 1, Comm: "nginx"},
		{PID: 31, PPID: 30, Comm: "nc"},
		{PID: 40, PPID: 1, Comm: "php"},
		{PID: 41, PPID: 40, Comm: "sh"}, // php CLI from cron
	}
	got := SuspiciousLineage(procs)
	if len(got) != 2 || got[0].PID != 11 || got[1].PID != 31 {
		t.Fatalf("lineage: %+v", got)
	}
	if ParentComm(procs, got[0]) != "php-fpm8.1" {
		t.Error("parent")
	}
}

func TestProcWatcherLineage(t *testing.T) {
	root := newLinkMapFS()
	root.addProc(10, 1, "nginx", "/usr/sbin/nginx", 5)
	root.addProc(11, 10, "sh", "/usr/bin/dash", 6)
	w := &ProcWatcher{Root: root, StateDir: t.TempDir()}
	evs := w.Tick()
	if len(evs) != 1 || evs[0].Kind != ProcLineage || evs[0].Args["parent"] != "nginx" || evs[0].Args["ppid"] != "10" {
		t.Fatalf("events: %+v", evs)
	}
	a, ok := NewRules(5).Feed(evs[0], newState())
	if !ok || a.ID != "alert.proc_lineage" || a.Fix != "sudo ls -l /proc/11/exe /proc/11/cwd && sudo kill 11" {
		t.Errorf("alert: %+v", a)
	}
	if again := w.Tick(); len(again) != 0 {
		t.Errorf("once: %+v", again)
	}
}

func TestMassFile(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	fsys := fstest.MapFS{}
	for i := 0; i < 60; i++ {
		fsys[fmt.Sprintf("var/www/html/p%02d.php", i)] = &fstest.MapFile{ModTime: now.Add(-10 * time.Second)}
	}
	for i := 0; i < 500; i++ {
		fsys[fmt.Sprintf("var/www/html/img/old%03d.png", i)] = &fstest.MapFile{ModTime: now.Add(-48 * time.Hour)}
	}
	n, sample := CountRecentChanges(fsys, "var/www", now.Add(-time.Minute))
	if n != 60 || len(sample) != 3 || sample[0] != "/var/www/html/p00.php" {
		t.Fatalf("count %d sample %v", n, sample)
	}

	w := &MassFileWatcher{FS: fsys, Dirs: []string{"var/www"}, Clock: func() time.Time { return now }}
	w.T = config.ThresholdsFor(config.Normal) // 200 per 60s: quiet
	if evs := w.Tick(); len(evs) != 0 {
		t.Errorf("normal must stay quiet for 60 files: %+v", evs)
	}
	w.T = config.ThresholdsFor(config.High) // 50 per 60s
	evs := w.Tick()
	if len(evs) != 1 || evs[0].Args["count"] != "60" || evs[0].Args["dir"] != "/var/www" {
		t.Fatalf("high: %+v", evs)
	}
	a, ok := NewRules(5).Feed(evs[0], newState())
	if !ok || a.Fix != "sudo find /var/www -type f -mmin -2 | head -50" {
		t.Errorf("alert: %+v", a)
	}
}
