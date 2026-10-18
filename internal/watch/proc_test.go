package watch

import (
	"os"
	"reflect"
	"testing"
	"testing/fstest"
)

func TestInventoryFixture(t *testing.T) {
	ps, err := Inventory(newProcFS("testdata/proc"))
	if err != nil {
		t.Fatal(err)
	}
	want := []Process{
		{PID: 1, PPID: 0, UID: 0, Exe: "/usr/lib/systemd/systemd", Cwd: "/",
			Cmdline: []string{"/sbin/init", "splash"}, Comm: "systemd", StartTicks: 5, CPUTicks: 3},
		{PID: 4242, PPID: 1, UID: 1000, Exe: "/tmp/y", ExeDeleted: true, Cwd: "/home/yosef",
			Cmdline: []string{"/tmp/y", "600"}, Comm: "evil) (x", StartTicks: 98765, CPUTicks: 3},
		{PID: 4300, PPID: 4242, UID: 33, Exe: "/tmp/x",
			Cmdline: []string{"/tmp/x", "600"}, Comm: "x", StartTicks: 123456, CPUTicks: 3},
	}
	// 5000 has no stat (exited mid-scan) and "sys" is not a pid: both skipped.
	if !reflect.DeepEqual(ps, want) {
		t.Errorf("Inventory =\n%+v\nwant\n%+v", ps, want)
	}
}

func TestReadProcessWithoutLinks(t *testing.T) {
	// A plain fs.FS (no ReadLink) still yields everything but exe/cwd.
	m := fstest.MapFS{
		"7/stat":   {Data: []byte("7 (kworker/0:1) I 2 0 0 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 42 0 0\n")},
		"7/comm":   {Data: []byte("kworker/0:1\n")},
		"7/status": {Data: []byte("Name:\tkworker\nUid:\tbogus\n")},
	}
	p, err := ReadProcess(m, 7)
	if err != nil {
		t.Fatal(err)
	}
	if p.PPID != 2 || p.StartTicks != 42 || p.UID != -1 || p.Exe != "" || p.Cmdline != nil || p.Comm != "kworker/0:1" {
		t.Errorf("got %+v", p)
	}
	if _, err := ReadProcess(fstest.MapFS{"8/stat": {Data: []byte("8 (x) S 1\n")}}, 8); err == nil {
		t.Error("short stat must be an error")
	}
	if _, err := ReadProcess(m, 9); err == nil {
		t.Error("missing pid must be an error")
	}
}

func TestOSInventorySeesSelf(t *testing.T) {
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("no /proc")
	}
	ps, err := OSInventory()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ps {
		if p.PID == os.Getpid() {
			if p.PPID != os.Getppid() || p.UID != os.Getuid() || p.Exe == "" {
				t.Errorf("self = %+v", p)
			}
			return
		}
	}
	t.Error("own pid not in inventory")
}
