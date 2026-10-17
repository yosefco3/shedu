package checks

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/yosefco3/shedu/internal/finding"
)

// SSH audits the *effective* sshd configuration via `sshd -T`, which resolves
// every Include and Match block. Reading sshd_config by hand would miss those.
type SSH struct {
	Dump func(ctx context.Context) ([]byte, error)
	// Service is the systemd unit to reload in fix commands: "ssh" on Debian/Ubuntu, "sshd" elsewhere.
	Service string
}

// NewSSH returns the production collector.
func NewSSH() *SSH {
	svc := "sshd"
	if _, err := os.Stat("/etc/debian_version"); err == nil {
		svc = "ssh"
	}
	return &SSH{
		Service: svc,
		Dump: func(ctx context.Context) ([]byte, error) {
			return exec.CommandContext(ctx, "sshd", "-T").Output()
		},
	}
}

func (s *SSH) Name() string { return "ssh" }

// Drop-in file read first by sshd (first value wins), so it overrides
// 50-cloud-init.conf and friends. -t validates before reloading.
const sshDropIn = "/etc/ssh/sshd_config.d/00-shedu.conf"

func (s *SSH) fix(directive string) string {
	return "echo '" + directive + "' | sudo tee -a " + sshDropIn + " && sudo sshd -t && sudo systemctl reload " + s.Service
}

// Run analyses `sshd -T`. No sshd → no findings. sshd present but not readable
// (not root) → a single Info "ssh.need_root".
func (s *SSH) Run(ctx context.Context) ([]finding.Finding, error) {
	out, err := s.Dump(ctx)
	if err != nil {
		if isNotInstalled(err) {
			return nil, nil
		}
		return []finding.Finding{{ID: "ssh.need_root", Severity: finding.Info, Evidence: err.Error()}}, nil
	}
	return s.analyse(ParseSSHD(out)), nil
}

func (s *SSH) analyse(cfg map[string]string) []finding.Finding {
	var fs []finding.Finding
	add := func(id string, sev finding.Severity, directive, key string) {
		fs = append(fs, finding.Finding{
			ID: id, Severity: sev, Fix: s.fix(directive),
			Evidence: key + " " + cfg[key],
		})
	}
	if cfg["permitemptypasswords"] == "yes" {
		add("ssh.empty_passwords", finding.Critical, "PermitEmptyPasswords no", "permitemptypasswords")
	}
	if cfg["passwordauthentication"] == "yes" {
		add("ssh.password_auth", finding.High, "PasswordAuthentication no", "passwordauthentication")
	}
	if cfg["permitrootlogin"] == "yes" {
		add("ssh.root_login", finding.High, "PermitRootLogin prohibit-password", "permitrootlogin")
	}
	if n, err := strconv.Atoi(cfg["maxauthtries"]); err == nil && n > 6 {
		add("ssh.max_auth_tries", finding.Low, "MaxAuthTries 4", "maxauthtries")
	}
	if cfg["x11forwarding"] == "yes" {
		add("ssh.x11_forwarding", finding.Info, "X11Forwarding no", "x11forwarding")
	}
	return fs
}

// ParseSSHD turns `sshd -T` output ("key value" per line) into a map with
// lowercase keys and values. Multi-word values are kept whole.
func ParseSSHD(out []byte) map[string]string {
	cfg := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		k, v, _ := strings.Cut(line, " ")
		cfg[strings.ToLower(k)] = strings.ToLower(strings.TrimSpace(v))
	}
	return cfg
}
