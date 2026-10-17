package checks

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/yosefco3/shedu/internal/finding"
)

func TestParseSSHD(t *testing.T) {
	cfg := ParseSSHD(fixture(t, "sshd_T_default_ubuntu.txt"))
	if cfg["passwordauthentication"] != "yes" || cfg["permitrootlogin"] != "prohibit-password" {
		t.Errorf("unexpected parse: %v", cfg)
	}
	if !strings.HasPrefix(cfg["ciphers"], "chacha20") || !strings.Contains(cfg["authorizedkeysfile"], " ") {
		t.Errorf("multi-word values must be kept whole: %q / %q", cfg["ciphers"], cfg["authorizedkeysfile"])
	}
	bad := ParseSSHD(fixture(t, "sshd_T_bad.txt"))
	if bad["permitrootlogin"] != "yes" {
		t.Errorf("keys and values must be lowercased: %v", bad)
	}
}

func TestSSHRun(t *testing.T) {
	cases := []struct {
		file string
		want map[string]finding.Severity
	}{
		{"sshd_T_default_ubuntu.txt", map[string]finding.Severity{
			"ssh.password_auth": finding.High, "ssh.x11_forwarding": finding.Info}},
		{"sshd_T_hardened.txt", map[string]finding.Severity{}},
		{"sshd_T_bad.txt", map[string]finding.Severity{
			"ssh.empty_passwords": finding.Critical, "ssh.password_auth": finding.High,
			"ssh.root_login": finding.High, "ssh.max_auth_tries": finding.Low}},
	}
	for _, c := range cases {
		s := &SSH{Service: "ssh", Dump: func(context.Context) ([]byte, error) { return fixture(t, c.file), nil }}
		fs, err := s.Run(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		got := ids(fs)
		if len(got) != len(c.want) {
			t.Errorf("%s: got %v, want %v", c.file, got, c.want)
		}
		for id, sev := range c.want {
			if got[id] != sev {
				t.Errorf("%s: %s = %v, want %v", c.file, id, got[id], sev)
			}
		}
		for _, f := range fs {
			if !strings.Contains(f.Fix, "00-shedu.conf") || !strings.Contains(f.Fix, "sshd -t") || !strings.HasSuffix(f.Fix, "reload ssh") {
				t.Errorf("%s: fix must write the drop-in, validate and reload: %q", f.ID, f.Fix)
			}
		}
	}
}

func TestSSHRunNoSSHD(t *testing.T) {
	s := &SSH{Dump: func(context.Context) ([]byte, error) { return nil, exec.ErrNotFound }}
	fs, err := s.Run(context.Background())
	if err != nil || len(fs) != 0 {
		t.Errorf("no sshd must mean no findings, got %v %v", fs, err)
	}
	s = &SSH{Dump: func(context.Context) ([]byte, error) { return nil, errors.New("Permission denied") }}
	fs, _ = s.Run(context.Background())
	if len(fs) != 1 || fs[0].ID != "ssh.need_root" {
		t.Errorf("unreadable sshd must yield ssh.need_root, got %v", fs)
	}
}
