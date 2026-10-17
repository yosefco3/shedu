package checks

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yosefco3/shedu/internal/finding"
)

func TestParseHexAddr(t *testing.T) {
	cases := []struct {
		in   string
		ip   string
		port int
	}{
		{"0100007F:0CEA", "127.0.0.1", 3306},
		{"00000000:0016", "0.0.0.0", 22},
		{"0A00000A:1F90", "10.0.0.10", 8080},
		{"00000000000000000000000000000000:0050", "::", 80},
		{"00000000000000000000000001000000:1F40", "::1", 8000},
		{"0000000000000000FFFF00000100007F:0050", "127.0.0.1", 80}, // IPv4-mapped renders as IPv4
	}
	for _, c := range cases {
		ip, port, err := parseHexAddr(c.in)
		if err != nil || ip.String() != c.ip || port != c.port {
			t.Errorf("parseHexAddr(%q) = %v:%d, %v; want %s:%d", c.in, ip, port, err, c.ip, c.port)
		}
	}
	if _, _, err := parseHexAddr("garbage"); err == nil {
		t.Error("garbage must fail")
	}
}

func TestParseProcNetTCP(t *testing.T) {
	f, _ := os.Open(filepath.Join("testdata", "proc_net_tcp_sample.txt"))
	defer f.Close()
	ls, err := ParseProcNetTCP(f, "tcp")
	if err != nil {
		t.Fatal(err)
	}
	if len(ls) != 5 {
		t.Fatalf("want 5 LISTEN sockets (ESTABLISHED row skipped), got %d", len(ls))
	}
	if ls[1].Addr.String() != "127.0.0.1" || ls[1].Port != 3306 || ls[1].Inode != 1002 {
		t.Errorf("row 1 = %+v", ls[1])
	}
}

func TestIsPublic(t *testing.T) {
	cases := map[string]bool{"0.0.0.0": true, "::": true, "127.0.0.1": false, "::1": false, "10.0.0.5": true, "::ffff:127.0.0.1": false}
	for s, want := range cases {
		if got := IsPublic(net.ParseIP(s)); got != want {
			t.Errorf("IsPublic(%s) = %v, want %v", s, got, want)
		}
	}
}

func testPorts(t *testing.T, ufw bool) *Ports {
	names := map[uint64]string{1001: "sshd", 1002: "mysqld", 1003: "redis-server", 1005: "systemd-resolve", 1006: "node", 2001: "nginx", 2002: "sshd", 2003: "python3"}
	return &Ports{
		HasUFW: ufw,
		Open: func(proto string) (io.ReadCloser, error) {
			return os.Open(filepath.Join("testdata", "proc_net_"+proto+"_sample.txt"))
		},
		Resolve: func(inode uint64) (int, string) { return int(inode), names[inode] },
	}
}

func TestPortsRun(t *testing.T) {
	fs, err := testPorts(t, true).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var db, dev, summary *finding.Finding
	for i := range fs {
		switch fs[i].ID {
		case "ports.db_public":
			db = &fs[i]
		case "ports.dev_public":
			dev = &fs[i]
		case "ports.summary":
			summary = &fs[i]
		}
	}
	if db == nil || db.Severity != finding.Critical || db.Args["service"] != "redis" || db.Args["process"] != "redis-server" {
		t.Errorf("redis on 0.0.0.0:6379 must be ports.db_public critical, got %+v", db)
	}
	if !strings.HasPrefix(db.Fix, "sudo ufw deny 6379/tcp") {
		t.Errorf("fix = %q", db.Fix)
	}
	if dev == nil || dev.Args["port"] != "8080" {
		t.Errorf("10.0.0.10:8080 (node) must be ports.dev_public, got %+v", dev)
	}
	if summary == nil || summary.Args["list"] != "22 sshd, 80 nginx, 6379 redis-server, 8080 node" {
		t.Errorf("summary = %+v", summary)
	}
	for _, f := range fs {
		if f.ID == "ports.db_public" && f.Args["port"] == "3306" {
			t.Error("mysql on loopback must not be reported")
		}
	}
	if len(fs) != 3 {
		t.Errorf("want exactly 3 findings, got %d: %v", len(fs), ids(fs))
	}
}

func TestPortsFixWithoutUFW(t *testing.T) {
	fs, _ := testPorts(t, false).Run(context.Background())
	for _, f := range fs {
		if f.ID == "ports.db_public" && !strings.Contains(f.Fix, "apt install -y ufw") {
			t.Errorf("without ufw the fix must install it: %q", f.Fix)
		}
	}
}
