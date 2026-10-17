package checks

import (
	"bufio"
	"bytes"
	"context"
	"os/exec"
	"regexp"
	"strings"

	"github.com/yosefco12/shedu/internal/finding"
)

// Firewall answers one question for the owner: is anything filtering inbound
// traffic at all? It accepts ufw, nftables or raw iptables as a "yes".
type Firewall struct {
	NFT      func(ctx context.Context) ([]byte, error) // `nft list ruleset`
	IPTables func(ctx context.Context) ([]byte, error) // `iptables -S`
	UFWConf  func() ([]byte, error)                    // /etc/ufw/ufw.conf
}

// NewFirewall returns the production collector.
func NewFirewall() *Firewall {
	return &Firewall{
		NFT: func(ctx context.Context) ([]byte, error) {
			return exec.CommandContext(ctx, "nft", "list", "ruleset").Output()
		},
		IPTables: func(ctx context.Context) ([]byte, error) { return exec.CommandContext(ctx, "iptables", "-S").Output() },
		UFWConf:  func() ([]byte, error) { return readFile("/etc/ufw/ufw.conf") },
	}
}

func (f *Firewall) Name() string { return "firewall" }

const fixUFW = "sudo apt install -y ufw && sudo ufw allow OpenSSH && sudo ufw --force enable"

// Run: ufw enabled → fine. Otherwise look at the live rulesets. If both tools
// are unreadable (not root) the answer is unknown → Info "firewall.need_root".
func (f *Firewall) Run(ctx context.Context) ([]finding.Finding, error) {
	conf, err := f.UFWConf()
	if err != nil {
		return nil, err
	}
	if UFWEnabled(conf) {
		return nil, nil
	}
	nft, nftErr := f.NFT(ctx)
	ipt, iptErr := f.IPTables(ctx)
	nftMissing, iptMissing := nftErr != nil && isNotInstalled(nftErr), iptErr != nil && isNotInstalled(iptErr)
	nftDenied, iptDenied := nftErr != nil && !nftMissing, iptErr != nil && !iptMissing
	if (nftDenied || nftMissing) && (iptDenied || iptMissing) && (nftDenied || iptDenied) {
		return []finding.Finding{{ID: "firewall.need_root", Severity: finding.Info}}, nil
	}
	switch Classify(nft, ipt) {
	case fwNone:
		return []finding.Finding{{ID: "firewall.none", Severity: finding.Medium, Fix: fixUFW}}, nil
	case fwAcceptAll:
		return []finding.Finding{{ID: "firewall.input_accept_all", Severity: finding.Low, Fix: fixUFW}}, nil
	}
	return nil, nil
}

// UFWEnabled parses /etc/ufw/ufw.conf for ENABLED=yes.
func UFWEnabled(conf []byte) bool {
	sc := bufio.NewScanner(bytes.NewReader(conf))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "ENABLED=") {
			return strings.EqualFold(strings.TrimPrefix(line, "ENABLED="), "yes")
		}
	}
	return false
}

type fwState int

const (
	fwNone      fwState = iota // no inbound filtering at all
	fwAcceptAll                // an input chain exists but drops nothing
	fwFiltering                // something is dropped or rejected
)

var (
	nftInputHook = regexp.MustCompile(`type\s+filter\s+hook\s+input`)
	nftDeny      = regexp.MustCompile(`(?m)(policy\s+(drop|reject)|\b(drop|reject)\b)`)
	iptInputRule = regexp.MustCompile(`(?m)^-A INPUT\b`)
	iptDeny      = regexp.MustCompile(`(?m)^(-P INPUT (DROP|REJECT)|-A INPUT .*-j (DROP|REJECT))`)
)

// Classify looks at `nft list ruleset` and `iptables -S` output together.
func Classify(nft, ipt []byte) fwState {
	hasChain := nftInputHook.Match(nft) || iptInputRule.Match(ipt) || bytes.Contains(ipt, []byte("-P INPUT DROP"))
	denies := nftDeny.Match(nft) || iptDeny.Match(ipt)
	switch {
	case denies:
		return fwFiltering
	case hasChain:
		return fwAcceptAll
	}
	return fwNone
}
