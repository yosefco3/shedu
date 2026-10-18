package watch

import (
	"testing"
	"testing/fstest"
)

func TestPreloadEnv(t *testing.T) {
	env := []byte("PATH=/usr/bin\x00LD_PRELOAD=/tmp/evil.so\x00HOME=/root\x00")
	if v := LDPreload(env); v != "/tmp/evil.so" {
		t.Errorf("LDPreload = %q", v)
	}
	if LDPreload([]byte("PATH=/usr/bin\x00")) != "" {
		t.Error("no LD_PRELOAD")
	}
	cases := map[string]bool{
		"/tmp/evil.so": true,
		"/usr/lib/x86_64-linux-gnu/libjemalloc.so.2":                false,
		"/usr/lib/x86_64-linux-gnu/libfakeroot/libfakeroot-sysv.so": false,
		"/home/bob/build/libfakeroot.so":                            false,
		"/usr/lib/libz.so:/dev/shm/x.so":                            true,
		"libsnoop.so":                                               true, // bare name: searched in odd places
	}
	for v, want := range cases {
		if got := SuspiciousPreload(v); got != want {
			t.Errorf("SuspiciousPreload(%q) = %v", v, got)
		}
	}
}

func TestProcWatcherPreload(t *testing.T) {
	root := newLinkMapFS()
	root.addProc(50, 1, "sshd", "/usr/sbin/sshd", 5)
	root.MapFS["50/environ"] = &fstest.MapFile{Data: []byte("LD_PRELOAD=/var/tmp/.l/hook.so\x00")}
	root.addProc(51, 1, "java", "/usr/bin/java", 6)
	root.MapFS["51/environ"] = &fstest.MapFile{Data: []byte("LD_PRELOAD=/usr/lib/libjemalloc.so\x00")}
	w := &ProcWatcher{Root: root, StateDir: t.TempDir()}
	evs := w.Tick()
	if len(evs) != 1 || evs[0].Kind != PreloadChanged || evs[0].Args["pid"] != "50" || evs[0].Args["value"] != "/var/tmp/.l/hook.so" {
		t.Fatalf("events: %+v", evs)
	}
	if again := w.Tick(); len(again) != 0 {
		t.Errorf("once per process: %+v", again)
	}
	a, ok := NewRules(5).Feed(evs[0], newState())
	if !ok || a.ID != "alert.preload_env" || a.Fix != `sudo tr '\0' '\n' < /proc/50/environ | grep LD_PRELOAD` {
		t.Errorf("alert: %+v", a)
	}
}

func TestPreloadWatcher(t *testing.T) {
	fsys := fstest.MapFS{"etc/hostname": {Data: []byte("x\n")}}
	dir := t.TempDir()
	w := &PreloadWatcher{FS: fsys, StateDir: dir}
	if evs := w.Tick(); len(evs) != 0 {
		t.Fatalf("no file must be silent: %+v", evs)
	}
	fsys["etc/ld.so.preload"] = &fstest.MapFile{Data: []byte("# comment\n/lib/x86_64-linux-gnu/libsystemd-shim.so\n")}
	evs := w.Tick()
	if len(evs) != 1 || evs[0].Args["content"] != "/lib/x86_64-linux-gnu/libsystemd-shim.so" || evs[0].Args["changed"] != "" {
		t.Fatalf("appeared: %+v", evs)
	}
	if evs := (&PreloadWatcher{FS: fsys, StateDir: dir}).Tick(); len(evs) != 0 {
		t.Errorf("restart must remember: %+v", evs)
	}
	fsys["etc/ld.so.preload"] = &fstest.MapFile{Data: []byte("/usr/local/lib/libhide.so\n")}
	if evs := w.Tick(); len(evs) != 1 || evs[0].Args["changed"] != "1" {
		t.Errorf("changed: %+v", evs)
	}
	a, ok := NewRules(5).Feed(evs[0], newState())
	if !ok || a.ID != "alert.preload_file" || a.Fix != PreloadFix {
		t.Errorf("alert: %+v", a)
	}
	delete(fsys, "etc/ld.so.preload")
	if evs := w.Tick(); len(evs) != 0 {
		t.Errorf("removed is quiet: %+v", evs)
	}
}
