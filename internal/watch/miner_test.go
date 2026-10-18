package watch

import (
	"fmt"
	"testing"
	"testing/fstest"
	"time"

	"github.com/yosefco3/shedu/internal/config"
)

// setCPU rewrites a fake process's stat with a CPU tick counter.
func (l linkMapFS) setCPU(pid, ppid int, comm string, start, ticks uint64) {
	l.MapFS[fmt.Sprintf("%d/stat", pid)] = &fstest.MapFile{Data: []byte(fmt.Sprintf(
		"%d (%s) R %d 0 0 0 -1 0 0 0 0 0 %d 0 0 0 20 0 1 0 %d 0 0\n", pid, comm, ppid, ticks, start))}
}

func TestCPUPercent(t *testing.T) {
	a := Process{PID: 7, StartTicks: 1, CPUTicks: 1000}
	b := Process{PID: 7, StartTicks: 1, CPUTicks: 1000 + 2400} // 24 s of CPU in 30 s
	if got := CPUPercent(a, b, 30*time.Second); got < 79.9 || got > 80.1 {
		t.Errorf("got %.2f want 80", got)
	}
	b4 := Process{PID: 7, StartTicks: 1, CPUTicks: 1000 + 12000} // four cores
	if got := CPUPercent(a, b4, 30*time.Second); got != 400 {
		t.Errorf("multi-core: %.2f", got)
	}
	if CPUPercent(a, Process{PID: 7, StartTicks: 2, CPUTicks: 5000}, time.Second) != 0 {
		t.Error("reused pid is a different process")
	}
}

func TestMinerHeuristic(t *testing.T) {
	root := newLinkMapFS()
	root.addProc(100, 1, "make", "/usr/bin/make", 10)           // busy build: CPU only
	root.addProc(200, 1, "x", "/tmp/.x/x", 20)                  // busy, from /tmp
	root.addProc(300, 1, "worker", "/usr/local/bin/worker", 30) // busy, talks to a pool
	root.MapFS["300/fd/3"] = &fstest.MapFile{}
	root.links["300/fd/3"] = "socket:[777]"
	root.MapFS["net/tcp"] = &fstest.MapFile{Data: []byte("h\n" +
		fmt.Sprintf("0: 0500000A:C738 %s:%04X 01 0:0 0:0 0 0 0 777\n", hexIP("51.15.1.2"), 14444))}

	clock := time.Unix(1_700_000_000, 0)
	w := &ProcWatcher{Root: root, StateDir: t.TempDir(), T: config.ThresholdsFor(config.Normal),
		Clock: func() time.Time { return clock }}
	var got []Event
	ticks := uint64(0)
	for i := 0; i < 4; i++ { // every process burns 90% of a core
		for _, p := range []struct {
			pid   int
			comm  string
			start uint64
		}{{100, "make", 10}, {200, "x", 20}, {300, "worker", 30}} {
			root.setCPU(p.pid, 1, p.comm, p.start, ticks)
		}
		for _, ev := range w.Tick() {
			if ev.Kind == MinerSuspected {
				got = append(got, ev)
			}
		}
		clock = clock.Add(30 * time.Second)
		ticks += 2700
	}
	if len(got) != 2 {
		t.Fatalf("want 2 miner events (not make), got %+v", got)
	}
	if got[0].Args["pid"] != "200" || got[0].Args["signal"] != "exe" || got[0].Args["cpu"] != "90" {
		t.Errorf("tmp miner: %+v", got[0].Args)
	}
	if got[1].Args["pid"] != "300" || got[1].Args["signal"] != "pool" || got[1].Args["dest"] != "51.15.1.2:14444" {
		t.Errorf("pool miner: %+v", got[1].Args)
	}
	a, ok := NewRules(5).Feed(got[1], newState())
	if !ok || a.ID != "alert.miner" {
		t.Errorf("alert: %+v", a)
	}
}

func TestMinerNeedsSustainedCPU(t *testing.T) {
	root := newLinkMapFS()
	root.addProc(200, 1, "xmrig", "/usr/bin/xmrig", 20)
	clock := time.Unix(1_700_000_000, 0)
	w := &ProcWatcher{Root: root, StateDir: t.TempDir(), T: config.ThresholdsFor(config.Normal), Clock: func() time.Time { return clock }}
	// one hot sample, then idle: never sustained
	for i, ticks := range []uint64{0, 2700, 2710, 2720} {
		root.setCPU(200, 1, "xmrig", 20, ticks)
		if evs := w.Tick(); len(evs) != 0 {
			t.Fatalf("sample %d: %+v", i, evs)
		}
		clock = clock.Add(30 * time.Second)
	}
}
