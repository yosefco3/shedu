package checks

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/yosefco3/shedu/internal/finding"
)

// Updates reports pending package updates and whether unattended upgrades run.
// Debian/Ubuntu only in phase 1; other distros get a single Info finding.
type Updates struct {
	// ListUpgradable returns the output of `apt list --upgradable`.
	ListUpgradable func(ctx context.Context) ([]byte, error)
	// AutoUpgradeConf returns /etc/apt/apt.conf.d/20auto-upgrades (nil if absent).
	AutoUpgradeConf func() ([]byte, error)
}

// NewUpdates returns the production collector.
func NewUpdates() *Updates {
	return &Updates{
		ListUpgradable: func(ctx context.Context) ([]byte, error) {
			cmd := exec.CommandContext(ctx, "apt", "list", "--upgradable")
			cmd.Env = append(cmd.Environ(), "LANG=C", "LC_ALL=C")
			var out bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = nil // apt warns about its unstable CLI; irrelevant here
			if err := cmd.Run(); err != nil {
				return nil, err
			}
			return out.Bytes(), nil
		},
		AutoUpgradeConf: func() ([]byte, error) {
			return readFile("/etc/apt/apt.conf.d/20auto-upgrades")
		},
	}
}

func (u *Updates) Name() string { return "updates" }

const fixUpgrade = "sudo apt update && sudo apt upgrade -y"
const fixAutoUpgrade = "sudo apt install -y unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades"

// Run collects and analyses. Missing apt → updates.unsupported_distro only.
func (u *Updates) Run(ctx context.Context) ([]finding.Finding, error) {
	out, err := u.ListUpgradable(ctx)
	if err != nil {
		if isNotInstalled(err) {
			return []finding.Finding{{ID: "updates.unsupported_distro", Severity: finding.Info}}, nil
		}
		return nil, fmt.Errorf("apt list --upgradable: %w", err)
	}
	total, security, names := ParseUpgradable(out)

	var fs []finding.Finding
	switch {
	case security >= 10:
		fs = append(fs, securityFinding(finding.Critical, total, security, names))
	case security >= 1:
		fs = append(fs, securityFinding(finding.High, total, security, names))
	case total > 0:
		fs = append(fs, finding.Finding{
			ID: "updates.pending", Severity: finding.Low, Fix: fixUpgrade,
			Args: map[string]string{"count": fmt.Sprint(total)},
		})
	}

	conf, err := u.AutoUpgradeConf()
	if err != nil {
		return nil, fmt.Errorf("read 20auto-upgrades: %w", err)
	}
	if !ParseAutoUpgrade(conf) {
		fs = append(fs, finding.Finding{ID: "updates.no_auto", Severity: finding.Medium, Fix: fixAutoUpgrade})
	}
	return fs, nil
}

func securityFinding(sev finding.Severity, total, security int, names []string) finding.Finding {
	if len(names) > 5 {
		names = names[:5]
	}
	return finding.Finding{
		ID: "updates.security_pending", Severity: sev, Fix: fixUpgrade,
		Args: map[string]string{
			"count":    fmt.Sprint(total),
			"security": fmt.Sprint(security),
			"names":    strings.Join(names, ", "),
		},
		Evidence: fmt.Sprintf("%d upgradable, %d from a security suite", total, security),
	}
}

// upgradableLine matches e.g.
//
//	openssl/jammy-security 3.0.2-0ubuntu1.15 amd64 [upgradable from: 3.0.2-0ubuntu1.12]
//
// The suite field may list several archives separated by commas.
var upgradableLine = regexp.MustCompile(`^([^/\s]+)/(\S+)\s+\S+\s+\S+\s+\[upgradable from:`)

// ParseUpgradable counts upgradable packages in `apt list --upgradable` output and
// which of them come from a security suite (archive name containing "security").
func ParseUpgradable(out []byte) (total, security int, securityNames []string) {
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		m := upgradableLine.FindStringSubmatch(strings.TrimSpace(sc.Text()))
		if m == nil {
			continue // "Listing... Done", blank lines, warnings
		}
		total++
		if strings.Contains(strings.ToLower(m[2]), "security") {
			security++
			securityNames = append(securityNames, m[1])
		}
	}
	return total, security, securityNames
}

var autoUpgradeLine = regexp.MustCompile(`APT::Periodic::Unattended-Upgrade\s+"(\d+)"`)

// ParseAutoUpgrade reports whether 20auto-upgrades enables unattended upgrades.
func ParseAutoUpgrade(conf []byte) bool {
	m := autoUpgradeLine.FindSubmatch(conf)
	return m != nil && string(m[1]) != "0"
}
