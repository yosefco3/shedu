package checks

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/yosefco12/shedu/internal/finding"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseUpgradable(t *testing.T) {
	cases := []struct {
		file                 string
		wantTotal, wantSec   int
		wantFirstSecurityPkg string
	}{
		{"apt_upgradable_mixed.txt", 7, 3, "curl"},
		{"apt_upgradable_none.txt", 0, 0, ""},
		{"apt_upgradable_security_many.txt", 13, 12, "pkg0"},
	}
	for _, c := range cases {
		total, sec, names := ParseUpgradable(fixture(t, c.file))
		if total != c.wantTotal || sec != c.wantSec {
			t.Errorf("%s: got total=%d security=%d, want %d/%d", c.file, total, sec, c.wantTotal, c.wantSec)
		}
		if c.wantFirstSecurityPkg != "" && (len(names) == 0 || names[0] != c.wantFirstSecurityPkg) {
			t.Errorf("%s: first security package = %v, want %q", c.file, names, c.wantFirstSecurityPkg)
		}
	}
}

func TestParseAutoUpgrade(t *testing.T) {
	cases := []struct {
		conf string
		want bool
	}{
		{`APT::Periodic::Update-Package-Lists "1";` + "\n" + `APT::Periodic::Unattended-Upgrade "1";`, true},
		{`APT::Periodic::Unattended-Upgrade "0";`, false},
		{``, false},
		{`APT::Periodic::Update-Package-Lists "1";`, false},
	}
	for _, c := range cases {
		if got := ParseAutoUpgrade([]byte(c.conf)); got != c.want {
			t.Errorf("ParseAutoUpgrade(%q) = %v, want %v", c.conf, got, c.want)
		}
	}
	if ParseAutoUpgrade(nil) {
		t.Error("nil conf must mean disabled")
	}
}

func ids(fs []finding.Finding) map[string]finding.Severity {
	m := map[string]finding.Severity{}
	for _, f := range fs {
		m[f.ID] = f.Severity
	}
	return m
}

func TestUpdatesRun(t *testing.T) {
	auto := []byte(`APT::Periodic::Unattended-Upgrade "1";`)
	cases := []struct {
		name  string
		list  string
		auto  []byte
		want  map[string]finding.Severity
		names string
	}{
		{"mixed, auto on", "apt_upgradable_mixed.txt", auto,
			map[string]finding.Severity{"updates.security_pending": finding.High}, "curl, libcurl4, openssl"},
		{"many security, auto off", "apt_upgradable_security_many.txt", nil,
			map[string]finding.Severity{"updates.security_pending": finding.Critical, "updates.no_auto": finding.Medium}, "pkg0, pkg1, pkg2, pkg3, pkg4"},
		{"nothing pending, auto on", "apt_upgradable_none.txt", auto, map[string]finding.Severity{}, ""},
	}
	for _, c := range cases {
		u := &Updates{
			ListUpgradable:  func(context.Context) ([]byte, error) { return fixture(t, c.list), nil },
			AutoUpgradeConf: func() ([]byte, error) { return c.auto, nil },
		}
		fs, err := u.Run(context.Background())
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := ids(fs)
		if len(got) != len(c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
		for id, sev := range c.want {
			if got[id] != sev {
				t.Errorf("%s: %s severity = %v, want %v", c.name, id, got[id], sev)
			}
		}
		for _, f := range fs {
			if f.ID == "updates.security_pending" && f.Args["names"] != c.names {
				t.Errorf("%s: names = %q, want %q", c.name, f.Args["names"], c.names)
			}
		}
	}
}

func TestUpdatesRunPendingOnly(t *testing.T) {
	u := &Updates{
		ListUpgradable: func(context.Context) ([]byte, error) {
			return []byte("Listing... Done\nvim/jammy-updates 1 amd64 [upgradable from: 0]\n"), nil
		},
		AutoUpgradeConf: func() ([]byte, error) { return []byte(`APT::Periodic::Unattended-Upgrade "1";`), nil },
	}
	fs, err := u.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(fs); got["updates.pending"] != finding.Low || len(got) != 1 {
		t.Errorf("got %v, want only updates.pending=low", got)
	}
}

func TestUpdatesRunNoApt(t *testing.T) {
	u := &Updates{
		ListUpgradable:  func(context.Context) ([]byte, error) { return nil, exec.ErrNotFound },
		AutoUpgradeConf: func() ([]byte, error) { return nil, nil },
	}
	fs, err := u.Run(context.Background())
	if err != nil || len(fs) != 1 || fs[0].ID != "updates.unsupported_distro" {
		t.Errorf("got %v, %v; want single updates.unsupported_distro", fs, err)
	}
}

type failingCheck struct{}

func (failingCheck) Name() string                                   { return "boom" }
func (failingCheck) Run(context.Context) ([]finding.Finding, error) { return nil, errors.New("kaput") }

type okCheck struct{}

func (okCheck) Name() string { return "ok" }
func (okCheck) Run(context.Context) ([]finding.Finding, error) {
	return []finding.Finding{{ID: "ok.finding", Severity: finding.Low}}, nil
}

func TestRunIsolatesFailures(t *testing.T) {
	r := Run(context.Background(), "host1", time.Unix(0, 0), []Check{failingCheck{}, okCheck{}})
	got := ids(r.Findings)
	if got["check.failed"] != finding.Info || got["ok.finding"] != finding.Low || len(got) != 2 {
		t.Errorf("got %v", got)
	}
	for _, f := range r.Findings {
		if f.ID == "check.failed" && (f.Args["name"] != "boom" || f.Args["err"] != "kaput") {
			t.Errorf("check.failed args = %v", f.Args)
		}
	}
	if r.Host != "host1" {
		t.Errorf("host = %q", r.Host)
	}
}
