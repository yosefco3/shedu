package checks

import (
	"context"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/yosefco12/shedu/internal/finding"
)

func TestParseShadowEmpty(t *testing.T) {
	got := ParseShadowEmpty(fixture(t, "shadow_sample.txt"))
	if len(got) != 1 || got[0] != "guest" {
		t.Errorf("want [guest], got %v", got)
	}
}

func TestParseSudoersNoPasswd(t *testing.T) {
	got := ParseSudoersNoPasswd([]string{string(fixture(t, "sudoers_sample.txt"))})
	if len(got) != 1 || !strings.HasPrefix(got[0], "deploy ") {
		t.Errorf("want only the deploy entry, got %v", got)
	}
	root := ParseSudoersNoPasswd([]string{"root ALL=(ALL) NOPASSWD: ALL"})
	if len(root) != 0 {
		t.Errorf("root is exempt, got %v", root)
	}
}

func TestUIDZeroUsers(t *testing.T) {
	passwd := []byte("root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0::/root:/bin/bash\nyosef:x:1000:1000::/home/yosef:/bin/bash\n")
	if got := UIDZeroUsers(passwd); len(got) != 1 || got[0] != "toor" {
		t.Errorf("want [toor], got %v", got)
	}
}

func acct(t *testing.T, shadowErr error, shadowMode fs.FileMode, sshdMode fs.FileMode, sshdUID int, ww []string) *Accounts {
	return &Accounts{
		Shadow: func() ([]byte, error) {
			if shadowErr != nil {
				return nil, shadowErr
			}
			return fixture(t, "shadow_sample.txt"), nil
		},
		Passwd:  func() ([]byte, error) { return []byte("root:x:0:0::/root:/bin/bash\n"), nil },
		Sudoers: func() ([]string, error) { return []string{string(fixture(t, "sudoers_sample.txt"))}, nil },
		Stat: func(path string) (fs.FileMode, int, error) {
			if path == "/etc/shadow" {
				return shadowMode, 0, nil
			}
			return sshdMode, sshdUID, nil
		},
		WorldWritable: func() ([]string, error) { return ww, nil },
	}
}

func TestAccountsRunAsRoot(t *testing.T) {
	a := acct(t, nil, 0o644, 0o644, 0, []string{"/etc/cron.d/x", "/etc/a", "/etc/b", "/etc/c", "/etc/d", "/etc/e", "/etc/f"})
	fs, err := a.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := ids(fs)
	want := map[string]finding.Severity{
		"accounts.empty_password": finding.Critical, "accounts.sudo_nopasswd": finding.Medium,
		"perms.shadow_world_readable": finding.Critical, "perms.world_writable_etc": finding.Medium,
	}
	if len(got) != len(want) {
		t.Errorf("got %v, want %v", got, want)
	}
	for id, sev := range want {
		if got[id] != sev {
			t.Errorf("%s = %v, want %v", id, got[id], sev)
		}
	}
	for _, f := range fs {
		if f.ID == "perms.world_writable_etc" && (f.Args["count"] != "7" || strings.Count(f.Args["paths"], ",") != 4) {
			t.Errorf("world-writable must count all and list 5: %v", f.Args)
		}
		if f.ID == "accounts.empty_password" && f.Fix != "sudo passwd -l guest" {
			t.Errorf("fix = %q", f.Fix)
		}
	}
}

func TestAccountsRunClean(t *testing.T) {
	a := acct(t, nil, 0o640, 0o644, 0, nil)
	a.Shadow = func() ([]byte, error) { return []byte("root:$6$x:1:0:99999:7:::\n"), nil }
	a.Sudoers = func() ([]string, error) { return []string{"%sudo ALL=(ALL:ALL) ALL\n"}, nil }
	fs, _ := a.Run(context.Background())
	if len(fs) != 0 {
		t.Errorf("clean host must have no findings, got %v", ids(fs))
	}
}

func TestAccountsRunWithoutRoot(t *testing.T) {
	a := acct(t, os.ErrPermission, 0o640, 0o664, 1000, nil)
	fs, err := a.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := ids(fs)
	if _, ok := got["accounts.need_root"]; !ok {
		t.Errorf("unreadable shadow must yield accounts.need_root, got %v", got)
	}
	if got["perms.sshd_config_writable"] != finding.High {
		t.Errorf("group-writable sshd_config owned by uid 1000 must be reported, got %v", got)
	}
	if _, ok := got["accounts.empty_password"]; ok {
		t.Error("no shadow, no empty-password findings")
	}
}
