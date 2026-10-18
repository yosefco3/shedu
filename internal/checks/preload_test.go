package checks

import (
	"context"
	"testing"
	"testing/fstest"

	"github.com/yosefco3/shedu/internal/watch"
)

func TestPreloadCheck(t *testing.T) {
	p := &Preload{
		Root: fstest.MapFS{"etc/ld.so.preload": {Data: []byte("/usr/lib/libprocesshider.so\n")}},
		Proc: fstest.MapFS{
			"10/environ": {Data: []byte("LD_PRELOAD=/tmp/k.so\x00")},
			"11/environ": {Data: []byte("TERM=xterm\x00")},
		},
		Inventory: func() ([]watch.Process, error) {
			return []watch.Process{{PID: 10, Comm: "cron"}, {PID: 11, Comm: "bash"}, {PID: 12, Comm: "gone"}}, nil
		},
	}
	fs, err := p.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 || fs[0].ID != "preload.file" || fs[0].Args["content"] != "/usr/lib/libprocesshider.so" ||
		fs[1].ID != "preload.env" || fs[1].Args["value"] != "/tmp/k.so" || fs[1].Args["pid"] != "10" {
		t.Fatalf("findings: %+v", fs)
	}
	p.Root = fstest.MapFS{}
	p.Proc = fstest.MapFS{}
	if fs, _ := p.Run(context.Background()); len(fs) != 0 {
		t.Errorf("clean host: %+v", fs)
	}
}
