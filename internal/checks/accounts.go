package checks

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/yosefco3/shedu/internal/finding"
)

// Accounts covers the classic signs of a weak or already-compromised host:
// password-less logins, extra root accounts, sudo without a password, and
// sensitive files that the wrong people can read or write.
type Accounts struct {
	Shadow        func() ([]byte, error)   // /etc/shadow (root only)
	Passwd        func() ([]byte, error)   // /etc/passwd
	Sudoers       func() ([]string, error) // /etc/sudoers + /etc/sudoers.d/* contents
	Stat          func(path string) (mode fs.FileMode, uid int, err error)
	WorldWritable func() ([]string, error) // regular files under /etc (depth ≤ 2) with o+w
}

// NewAccounts returns the production collector.
func NewAccounts() *Accounts {
	return &Accounts{
		Shadow: func() ([]byte, error) { return os.ReadFile("/etc/shadow") },
		Passwd: func() ([]byte, error) { return os.ReadFile("/etc/passwd") },
		Sudoers: func() ([]string, error) {
			paths, _ := filepath.Glob("/etc/sudoers.d/*")
			sort.Strings(paths)
			paths = append([]string{"/etc/sudoers"}, paths...)
			var out []string
			for _, p := range paths {
				b, err := os.ReadFile(p)
				if err != nil {
					if errors.Is(err, os.ErrNotExist) {
						continue
					}
					return nil, err
				}
				out = append(out, string(b))
			}
			return out, nil
		},
		Stat: func(path string) (fs.FileMode, int, error) {
			st, err := os.Stat(path)
			if err != nil {
				return 0, 0, err
			}
			uid := -1
			if sys, ok := st.Sys().(*syscall.Stat_t); ok {
				uid = int(sys.Uid)
			}
			return st.Mode(), uid, nil
		},
		WorldWritable: func() ([]string, error) { return worldWritableUnder("/etc", 2) },
	}
}

func (a *Accounts) Name() string { return "accounts" }

// Run never fails on permission problems: without root it reports what it can
// plus a single Info "accounts.need_root".
func (a *Accounts) Run(ctx context.Context) ([]finding.Finding, error) {
	var fs []finding.Finding
	needRoot := false

	if shadow, err := a.Shadow(); err == nil {
		for _, u := range ParseShadowEmpty(shadow) {
			fs = append(fs, finding.Finding{ID: "accounts.empty_password", Severity: finding.Critical,
				Args: map[string]string{"user": u}, Fix: "sudo passwd -l " + u})
		}
	} else if errors.Is(err, os.ErrPermission) {
		needRoot = true
	} else {
		return nil, err
	}

	passwd, err := a.Passwd()
	if err != nil {
		return nil, err
	}
	for _, u := range UIDZeroUsers(passwd) {
		fs = append(fs, finding.Finding{ID: "accounts.uid0_extra", Severity: finding.Critical,
			Args: map[string]string{"user": u}, Evidence: u + " has uid 0"})
	}

	if files, err := a.Sudoers(); err == nil {
		for _, e := range ParseSudoersNoPasswd(files) {
			fs = append(fs, finding.Finding{ID: "accounts.sudo_nopasswd", Severity: finding.Medium,
				Args: map[string]string{"entry": e}, Fix: "sudo visudo", Evidence: e})
		}
	} else if errors.Is(err, os.ErrPermission) {
		needRoot = true
	} else {
		return nil, err
	}

	if mode, _, err := a.Stat("/etc/shadow"); err == nil && mode.Perm()&0o004 != 0 {
		fs = append(fs, finding.Finding{ID: "perms.shadow_world_readable", Severity: finding.Critical,
			Fix: "sudo chmod 640 /etc/shadow", Evidence: mode.String()})
	}
	if mode, uid, err := a.Stat("/etc/ssh/sshd_config"); err == nil && (mode.Perm()&0o022 != 0 || uid > 0) {
		fs = append(fs, finding.Finding{ID: "perms.sshd_config_writable", Severity: finding.High,
			Fix: "sudo chown root:root /etc/ssh/sshd_config && sudo chmod 644 /etc/ssh/sshd_config", Evidence: mode.String()})
	}
	if paths, err := a.WorldWritable(); err == nil && len(paths) > 0 {
		shown := paths
		if len(shown) > 5 {
			shown = shown[:5]
		}
		fs = append(fs, finding.Finding{ID: "perms.world_writable_etc", Severity: finding.Medium,
			Args: map[string]string{"count": itoa(len(paths)), "paths": strings.Join(shown, ", ")},
			Fix:  "sudo chmod o-w " + strings.Join(shown, " ")})
	}

	if needRoot {
		fs = append(fs, finding.Finding{ID: "accounts.need_root", Severity: finding.Info})
	}
	return fs, nil
}

func itoa(n int) string { return strconv.Itoa(n) }

// ParseShadowEmpty returns users whose password field is empty: they can log in
// with no password at all. Locked ("!", "*") and hashed entries are fine.
func ParseShadowEmpty(shadow []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(shadow))
	for sc.Scan() {
		f := strings.Split(sc.Text(), ":")
		if len(f) >= 2 && f[0] != "" && f[1] == "" {
			out = append(out, f[0])
		}
	}
	return out
}

// UIDZeroUsers returns every passwd entry with uid 0 other than root.
func UIDZeroUsers(passwd []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(passwd))
	for sc.Scan() {
		f := strings.Split(sc.Text(), ":")
		if len(f) >= 3 && f[2] == "0" && f[0] != "root" {
			out = append(out, f[0])
		}
	}
	return out
}

// nopasswdAll matches "user HOST=(RUNAS) NOPASSWD: ALL" (tags and runas optional).
var nopasswdAll = regexp.MustCompile(`^\s*(\S+)\s+\S+=.*NOPASSWD:\s*ALL\s*$`)

// ParseSudoersNoPasswd returns sudoers entries that grant *every* command
// without a password, except for root itself. A NOPASSWD for one specific
// command is a deliberate choice and not reported.
func ParseSudoersNoPasswd(files []string) []string {
	var out []string
	for _, content := range files {
		sc := bufio.NewScanner(strings.NewReader(content))
		for sc.Scan() {
			line := sc.Text()
			if i := strings.Index(line, "#"); i >= 0 && !strings.HasPrefix(strings.TrimSpace(line), "#include") {
				line = line[:i]
			}
			m := nopasswdAll.FindStringSubmatch(line)
			if m == nil || m[1] == "root" {
				continue
			}
			out = append(out, strings.Join(strings.Fields(line), " "))
		}
	}
	return out
}

// worldWritableUnder lists regular files with the other-write bit under root,
// descending at most maxDepth directories. Symlinks are skipped.
func worldWritableUnder(root string, maxDepth int) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable dir: skip, don't fail the whole check
		}
		depth := strings.Count(strings.TrimPrefix(path, root), string(os.PathSeparator))
		if d.IsDir() {
			if depth >= maxDepth {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 || !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err == nil && info.Mode().Perm()&0o002 != 0 {
			out = append(out, path)
		}
		return nil
	})
	return out, err
}
