package watch

import (
	"fmt"
	"testing"
	"testing/fstest"
	"time"

	"github.com/yosefco3/shedu/internal/i18n"
)

// linkMapFS is an in-memory /proc with readlink support.
type linkMapFS struct {
	fstest.MapFS
	links map[string]string
}

func (l linkMapFS) ReadLink(name string) (string, error) {
	if t, ok := l.links[name]; ok {
		return t, nil
	}
	return "", fmt.Errorf("no link %s", name)
}

// addProc adds one process to a fake /proc.
func (l linkMapFS) addProc(pid, ppid int, comm, exe string, start uint64) {
	d := fmt.Sprint(pid)
	l.MapFS[d+"/stat"] = &fstest.MapFile{Data: []byte(fmt.Sprintf("%d (%s) S %d 0 0 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 %d 0 0\n", pid, comm, ppid, start))}
	l.MapFS[d+"/status"] = &fstest.MapFile{Data: []byte("Uid:\t1000\t1000\t1000\t1000\n")}
	l.MapFS[d+"/comm"] = &fstest.MapFile{Data: []byte(comm + "\n")}
	l.MapFS[d+"/cmdline"] = &fstest.MapFile{Data: []byte(comm + "\x00")}
	if exe != "" {
		l.links[d+"/exe"] = exe
	}
}

func newLinkMapFS() linkMapFS { return linkMapFS{fstest.MapFS{}, map[string]string{}} }

func TestSuspiciousExec(t *testing.T) {
	cases := map[string]Process{
		"":                {Exe: "/usr/sbin/nginx"},
		ReasonTmpExec:     {Exe: "/tmp/x"},
		ReasonDeletedExec: {Exe: "/home/bob/.cache/k", ExeDeleted: true},
	}
	for want, p := range cases {
		if got := SuspiciousExec(p); got != want {
			t.Errorf("%+v: got %q want %q", p, got, want)
		}
	}
	more := []struct {
		p    Process
		want string
	}{
		{Process{Exe: "/dev/shm/.x", ExeDeleted: true}, ReasonDeletedExec},
		{Process{Exe: "/var/tmp/.x"}, ReasonTmpExec},
		{Process{Exe: "/usr/sbin/sshd", ExeDeleted: true}, ""}, // apt upgrade leftover
		{Process{Exe: "/memfd:payload"}, ReasonDeletedExec},    // fileless
		{Process{Exe: "/memfd:runc_cloned:/proc/self/exe"}, ""},
		{Process{Exe: ""}, ""}, // kernel thread / no permission
	}
	for _, c := range more {
		if got := SuspiciousExec(c.p); got != c.want {
			t.Errorf("%+v: got %q want %q", c.p, got, c.want)
		}
	}
}

func TestProcWatcherReportsOnce(t *testing.T) {
	root := newLinkMapFS()
	root.addProc(1, 0, "systemd", "/usr/lib/systemd/systemd", 1)
	root.addProc(100, 1, "x", "/tmp/x", 500)
	root.addProc(101, 1, "y", "/tmp/y (deleted)", 600)
	root.addProc(102, 1, "sshd", "/usr/sbin/sshd (deleted)", 700)
	dir := t.TempDir()
	w := &ProcWatcher{Root: root, StateDir: dir, UserName: func(int) string { return "bob" }}

	evs := w.Tick()
	if len(evs) != 2 {
		t.Fatalf("want 2 events, got %+v", evs)
	}
	if evs[0].Kind != ProcSuspicious || evs[0].Args["reason"] != ReasonTmpExec || evs[0].Args["user"] != "bob" ||
		evs[1].Args["reason"] != ReasonDeletedExec || evs[1].Args["exe"] != "/tmp/y" {
		t.Errorf("events: %+v", evs)
	}
	if again := w.Tick(); len(again) != 0 {
		t.Errorf("second tick must be quiet: %+v", again)
	}
	// a restarted daemon remembers what it already reported
	w2 := &ProcWatcher{Root: root, StateDir: dir}
	if again := w2.Tick(); len(again) != 0 {
		t.Errorf("after restart must be quiet: %+v", again)
	}
	// the pid is reused by a new process: that is a new instance, report it
	root.addProc(100, 1, "x", "/tmp/x", 999)
	if evs := w2.Tick(); len(evs) != 1 || evs[0].Args["pid"] != "100" {
		t.Errorf("reused pid: %+v", evs)
	}
	if len(w2.st.Reported) != 2 {
		t.Errorf("state must forget dead processes: %v", w2.st.Reported)
	}
}

func TestProcAlert(t *testing.T) {
	st := newState()
	r := NewRules(5)
	r.Clock = func() time.Time { return time.Unix(1000, 0) }
	ev := Event{Kind: ProcSuspicious, Args: map[string]string{"reason": ReasonDeletedExec, "pid": "42", "exe": "/tmp/y", "comm": "y", "user": "bob", "cmd": "/tmp/y 600"}}
	a, ok := r.Feed(ev, st)
	if !ok || a.ID != "alert.proc_deleted_exec" || a.Fix != "sudo cp /proc/42/exe /root/suspect-42.bin && sudo kill 42" {
		t.Fatalf("alert: %+v %v", a, ok)
	}
	if m := i18n.Render(i18n.He, a.ID, a.Args); m.Title == a.ID {
		t.Error("missing Hebrew text")
	}
	if _, again := r.Feed(ev, st); again {
		t.Error("same process must not alert twice")
	}
}
