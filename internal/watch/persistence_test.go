package watch

import (
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/yosefco3/shedu/internal/finding"
)

func persistFixture() fstest.MapFS {
	return fstest.MapFS{
		"etc/crontab":                                              {Data: []byte("17 * * * * root cd / && run-parts --report /etc/cron.hourly\n")},
		"etc/cron.d/e2scrub_all":                                   {Data: []byte("30 3 * * 0 root /sbin/e2scrub_all\n")},
		"etc/cron.daily/.placeholder":                              {Data: []byte("")},
		"etc/cron.daily/apt-compat":                                {Data: []byte("#!/bin/sh\n")},
		"var/spool/cron/crontabs/yosef":                            {Data: []byte("0 4 * * * /home/yosef/backup.sh\n")},
		"etc/systemd/system/shedu.service":                         {Data: []byte("[Service]\nExecStart=/usr/local/bin/shedu run\n")},
		"etc/systemd/system/multi-user.target.wants/shedu.service": {Data: []byte("[Service]\nExecStart=/usr/local/bin/shedu run\n")},
		"etc/systemd/system/a/b/c/too-deep.service":                {Data: []byte("x")},
		"home/bob/.config/systemd/user/sync.service":               {Data: []byte("[Service]\nExecStart=/usr/bin/rclone sync\n")},
		"etc/passwd": {Data: []byte("not persistence\n")},
	}
}

func TestScanPersistence(t *testing.T) {
	items, err := ScanPersistence(persistFixture())
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, it := range items {
		paths = append(paths, it.Source+":"+it.Path)
	}
	want := "cron:/etc/cron.d/e2scrub_all cron:/etc/cron.daily/apt-compat cron:/etc/crontab " +
		"systemd:/etc/systemd/system/multi-user.target.wants/shedu.service systemd:/etc/systemd/system/shedu.service " +
		"systemd:/home/bob/.config/systemd/user/sync.service cron:/var/spool/cron/crontabs/yosef"
	if got := strings.Join(paths, " "); got != want {
		t.Errorf("items:\n got %s\nwant %s", got, want)
	}
	fixes := map[string]string{
		"/var/spool/cron/crontabs/yosef":              "sudo crontab -l -u yosef",
		"/etc/systemd/system/shedu.service":           "systemctl cat shedu.service",
		"/home/bob/.config/systemd/user/sync.service": "sudo cat /home/bob/.config/systemd/user/sync.service",
	}
	for _, it := range items {
		if want, ok := fixes[it.Path]; ok && PersistFix(it) != want {
			t.Errorf("fix %s = %q", it.Path, PersistFix(it))
		}
	}
}

func TestPersistenceWatcher(t *testing.T) {
	fsys := persistFixture()
	dir := t.TempDir()
	w := &PersistenceWatcher{FS: fsys, StateDir: dir, Clock: func() time.Time { return time.Unix(1000, 0) }}
	if evs := w.Tick(); len(evs) != 0 {
		t.Fatalf("baseline must be silent: %+v", evs)
	}
	if evs := w.Tick(); len(evs) != 0 {
		t.Fatalf("no change must be silent: %+v", evs)
	}
	// acceptance test 3: a cron line is added for the user
	fsys["var/spool/cron/crontabs/yosef"] = &fstest.MapFile{Data: []byte("0 4 * * * /home/yosef/backup.sh\n*/5 * * * * /bin/true\n")}
	fsys["etc/systemd/system/evil.service"] = &fstest.MapFile{Data: []byte("[Service]\nExecStart=/tmp/.x\n")}
	w2 := &PersistenceWatcher{FS: fsys, StateDir: dir} // also proves the baseline was saved
	evs := w2.Tick()
	if len(evs) != 2 {
		t.Fatalf("want 2 events, got %+v", evs)
	}
	ch, nw := evs[1], evs[0]
	if ch.Args["path"] != "/var/spool/cron/crontabs/yosef" || ch.Args["changed"] != "1" || ch.Args["user_level"] != "1" ||
		ch.Args["diff"] != "+ */5 * * * * /bin/true" {
		t.Errorf("changed crontab: %+v", ch.Args)
	}
	if nw.Args["path"] != "/etc/systemd/system/evil.service" || nw.Args["changed"] != "" || !strings.Contains(nw.Args["diff"], "+ ExecStart=/tmp/.x") {
		t.Errorf("new unit: %+v", nw.Args)
	}
	if evs := w2.Tick(); len(evs) != 0 {
		t.Errorf("reported once: %+v", evs)
	}
	delete(fsys, "etc/systemd/system/evil.service")
	if evs := w2.Tick(); len(evs) != 0 {
		t.Errorf("removal is not alerted: %+v", evs)
	}
	fsys["etc/systemd/system/evil.service"] = &fstest.MapFile{Data: []byte("[Service]\nExecStart=/tmp/.x\n")}
	if evs := w2.Tick(); len(evs) != 1 {
		t.Errorf("re-added after removal must alert again: %+v", evs)
	}

	r := NewRules(5)
	a, ok := r.Feed(ch, newState())
	if !ok || a.ID != "alert.persistence_new" || a.Fix != "sudo crontab -l -u yosef" || a.Severity != finding.High {
		t.Errorf("alert: %+v", a)
	}
}
