package checks

import (
	"context"
	"testing"

	"github.com/yosefco3/shedu/internal/watch"
)

func TestProcessesCheck(t *testing.T) {
	p := &Processes{
		Inventory: func() ([]watch.Process, error) {
			return []watch.Process{
				{PID: 1, Exe: "/usr/lib/systemd/systemd", Comm: "systemd"},
				{PID: 10, Exe: "/tmp/x", Comm: "x", Cmdline: []string{"/tmp/x", "600"}},
				{PID: 11, Exe: "/var/tmp/y", ExeDeleted: true, Comm: "y"},
				{PID: 12, Exe: "/root/.k", ExeDeleted: true, Comm: "k"},
			}, nil
		},
		IsRoot: true,
	}
	fs, err := p.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 3 || fs[0].ID != "proc.tmp_exec" || fs[1].ID != "proc.deleted_exec" || fs[2].ID != "proc.deleted_exec" {
		t.Fatalf("findings: %+v", fs)
	}
	if fs[0].Args["cmd"] != "/tmp/x 600" || fs[0].Fix != "sudo ls -l /proc/10/exe /proc/10/cwd && sudo kill 10" {
		t.Errorf("args/fix: %+v", fs[0])
	}
	p.IsRoot = false
	fs, _ = p.Run(context.Background())
	if fs[len(fs)-1].ID != "proc.need_root" {
		t.Error("non-root run must say it was partial")
	}
}
