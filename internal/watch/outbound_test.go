package watch

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/yosefco3/shedu/internal/config"
)

func TestParseProcNetTCP(t *testing.T) {
	f, err := os.Open("testdata/net_tcp.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cs, err := ParseProcNetTCP(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 5 {
		t.Fatalf("rows: %d", len(cs))
	}
	c := cs[2]
	if !c.LocalIP.Equal(net.ParseIP("10.0.0.5")) || c.LocalPort != 51000 || !c.RemoteIP.Equal(net.ParseIP("93.184.215.14")) ||
		c.RemotePort != 443 || c.State != TCPEstablished || c.Inode != 1002 {
		t.Errorf("row 2: %+v", c)
	}
	out := Outgoing(cs)
	// inbound ssh (local port 22 listens), loopback and the listener are dropped
	if len(out) != 2 || out[0].Inode != 1002 || out[1].State != TCPTimeWait || out[1].RemotePort != 80 {
		t.Errorf("outgoing: %+v", out)
	}

	b, _ := os.ReadFile("testdata/net_tcp6.txt")
	cs6, err := ParseProcNetTCP(strings.NewReader(string(b)))
	if err != nil || len(cs6) != 2 {
		t.Fatalf("tcp6: %v %+v", err, cs6)
	}
	if cs6[0].RemoteIP.String() != "93.184.215.14" || cs6[0].RemotePort != 443 {
		t.Errorf("v4-mapped: %+v", cs6[0])
	}
	if _, err := ParseProcNetTCP(strings.NewReader("h\n 0: zz:1 00:00 01 0 0 0 0 0 0 0\n")); err == nil {
		t.Error("bad hex must fail")
	}
}

// netFS builds a fake /proc with one connection table and socket owners.
type netFS struct {
	linkMapFS
	rows []string
}

func hexIP(ip string) string {
	v := net.ParseIP(ip).To4()
	return fmt.Sprintf("%02X%02X%02X%02X", v[3], v[2], v[1], v[0])
}

func (n *netFS) set(rows ...string) {
	n.MapFS["net/tcp"] = &fstest.MapFile{Data: []byte("header\n" + strings.Join(rows, "\n") + "\n")}
}

// row: an established (or TIME_WAIT when inode is 0) outgoing connection.
func row(lport int, ip string, rport int, inode int) string {
	st := TCPEstablished
	if inode == 0 {
		st = TCPTimeWait
	}
	return fmt.Sprintf("0: 0500000A:%04X %s:%04X %s 0:0 0:0 0 0 0 %d", lport, hexIP(ip), rport, st, inode)
}

func newNetFS() *netFS {
	n := &netFS{linkMapFS: newLinkMapFS()}
	n.addProc(500, 1, "curl", "/usr/bin/curl", 10)
	n.addProc(600, 1, "agent", "/usr/bin/agent", 20)
	for pid, inodes := range map[int][]int{500: {1002, 1003}, 600: {3000, 3001, 3002, 3003, 3004, 3005, 3006, 3007}} {
		for i, ino := range inodes {
			name := fmt.Sprintf("%d/fd/%d", pid, i+3)
			n.MapFS[name] = &fstest.MapFile{}
			n.links[name] = fmt.Sprintf("socket:[%d]", ino)
		}
	}
	return n
}

func TestOutboundNewDestination(t *testing.T) {
	root := newNetFS()
	clock := time.Unix(1_700_000_000, 0)
	var logged []string
	th := config.ThresholdsFor(config.High) // OUTBOUND_ALERTS=all
	w := &OutboundWatcher{Root: root, StateDir: t.TempDir(), T: th, Clock: func() time.Time { return clock },
		Log: func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) }}

	root.set(row(51000, "93.184.215.14", 443, 1002))
	if evs := w.Tick(); len(evs) != 0 || len(logged) != 0 {
		t.Fatalf("baseline must be silent: %+v %v", evs, logged)
	}
	clock = clock.Add(30 * time.Second)
	root.set(row(51000, "93.184.215.14", 443, 1002), row(51001, "1.1.1.1", 443, 1003))
	evs := w.Tick()
	if len(evs) != 1 || evs[0].Kind != OutboundNew || evs[0].Args["comm"] != "curl" || evs[0].Args["ip"] != "1.1.1.1" || evs[0].Args["pid"] != "500" {
		t.Fatalf("new destination: %+v", evs)
	}
	if len(logged) != 1 || !strings.Contains(logged[0], "1.1.1.1:443 for curl") {
		t.Errorf("log: %v", logged)
	}
	clock = clock.Add(30 * time.Second)
	if evs := w.Tick(); len(evs) != 0 {
		t.Errorf("same destination again must be quiet: %+v", evs)
	}
	// the connection closed (TIME_WAIT, no owner): still credited to curl, not new
	clock = clock.Add(30 * time.Second)
	root.set(row(51001, "1.1.1.1", 443, 0))
	if evs := w.Tick(); len(evs) != 0 || len(w.st.Dest["?"]) != 0 {
		t.Errorf("closed connection: %+v %+v", evs, w.st.Dest)
	}

	// default mode (beacon): new destinations are logged but not alerted
	w2 := &OutboundWatcher{Root: root, StateDir: t.TempDir(), T: config.ThresholdsFor(config.Normal), Clock: func() time.Time { return clock }}
	w2.Tick()
	root.set(row(51002, "8.8.8.8", 53, 1002))
	if evs := w2.Tick(); len(evs) != 0 {
		t.Errorf("beacon mode must not alert new destinations: %+v", evs)
	}
}

func TestOutboundStateSurvivesRestart(t *testing.T) {
	root := newNetFS()
	dir := t.TempDir()
	clock := time.Unix(1_700_000_000, 0)
	th := config.ThresholdsFor(config.High)
	mk := func() *OutboundWatcher {
		return &OutboundWatcher{Root: root, StateDir: dir, T: th, Clock: func() time.Time { return clock }}
	}
	root.set(row(51000, "93.184.215.14", 443, 1002))
	mk().Tick()
	clock = clock.Add(time.Hour)
	if evs := mk().Tick(); len(evs) != 0 {
		t.Errorf("known destination after restart: %+v", evs)
	}
	clock = clock.Add(8 * 24 * time.Hour) // high: 7 days window
	if evs := mk().Tick(); len(evs) != 1 {
		t.Errorf("destination unseen past the window is new again: %+v", evs)
	}
}

func TestOutboundBeacon(t *testing.T) {
	root := newNetFS()
	clock := time.Unix(1_700_000_000, 0)
	w := &OutboundWatcher{Root: root, StateDir: t.TempDir(), Interval: 30 * time.Second,
		T: config.ThresholdsFor(config.Normal), Clock: func() time.Time { return clock }}
	root.set()
	w.Tick() // baseline, nothing open
	var got []Event
	for i := 0; i < 8; i++ { // agent opens a fresh connection every 5 minutes
		clock = clock.Add(5*time.Minute + time.Duration(i%3)*7*time.Second)
		root.set(row(52000+i, "45.9.20.1", 8443, 3000+i))
		got = append(got, w.Tick()...)
	}
	if len(got) != 1 || got[0].Kind != OutboundBeacon || got[0].Args["comm"] != "agent" || got[0].Args["count"] != "6" {
		t.Fatalf("want exactly one beacon event, got %+v", got)
	}
}

func TestIsBeacon(t *testing.T) {
	regular := []int64{0, 300, 600, 905, 1200, 1500}
	if every, ok := IsBeacon(regular, 30*time.Second); !ok || every < 4*time.Minute {
		t.Errorf("regular: %v %v", every, ok)
	}
	if _, ok := IsBeacon([]int64{0, 300, 400, 1500, 1600, 3000}, 30*time.Second); ok {
		t.Error("irregular must not be a beacon")
	}
	if _, ok := IsBeacon([]int64{0, 30, 60, 90, 120, 150}, 30*time.Second); ok {
		t.Error("period below two polls is not measurable")
	}
	if _, ok := IsBeacon(regular[:4], 30*time.Second); ok {
		t.Error("too few starts")
	}
}
