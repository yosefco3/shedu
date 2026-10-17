package checks

import (
	"context"
	"errors"
	"os/exec"
	"testing"

	"github.com/yosefco12/shedu/internal/finding"
)

func fw(t *testing.T, nftFile, iptFile string, nftErr, iptErr error, ufw string) *Firewall {
	return &Firewall{
		NFT: func(context.Context) ([]byte, error) {
			if nftErr != nil {
				return nil, nftErr
			}
			return fixture(t, nftFile), nil
		},
		IPTables: func(context.Context) ([]byte, error) {
			if iptErr != nil {
				return nil, iptErr
			}
			return fixture(t, iptFile), nil
		},
		UFWConf: func() ([]byte, error) { return []byte(ufw), nil },
	}
}

func TestFirewallRun(t *testing.T) {
	denied := errors.New("Operation not permitted")
	cases := []struct {
		name string
		f    *Firewall
		want string // expected single finding ID, "" for none
	}{
		{"nft drop policy", fw(t, "nft_drop.txt", "iptables_empty.txt", nil, nil, "ENABLED=no"), ""},
		{"nft accept-all chain", fw(t, "nft_accept_all.txt", "iptables_empty.txt", nil, nil, "ENABLED=no"), "firewall.input_accept_all"},
		{"nothing at all", fw(t, "", "iptables_empty.txt", exec.ErrNotFound, nil, "ENABLED=no"), "firewall.none"},
		{"iptables rules only", fw(t, "", "iptables_rules.txt", exec.ErrNotFound, nil, ""), ""},
		{"ufw enabled wins", fw(t, "", "", exec.ErrNotFound, exec.ErrNotFound, "# conf\nENABLED=yes\nLOGLEVEL=low"), ""},
		{"not root", fw(t, "", "", denied, denied, "ENABLED=no"), "firewall.need_root"},
		{"not root, iptables missing", fw(t, "", "", denied, exec.ErrNotFound, ""), "firewall.need_root"},
		{"both missing", fw(t, "", "", exec.ErrNotFound, exec.ErrNotFound, ""), "firewall.none"},
	}
	for _, c := range cases {
		fs, err := c.f.Run(context.Background())
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		switch {
		case c.want == "" && len(fs) != 0:
			t.Errorf("%s: want no findings, got %v", c.name, ids(fs))
		case c.want != "" && (len(fs) != 1 || fs[0].ID != c.want):
			t.Errorf("%s: want %s, got %v", c.name, c.want, ids(fs))
		}
	}
	fs, _ := fw(t, "", "iptables_empty.txt", exec.ErrNotFound, nil, "ENABLED=no").Run(context.Background())
	if fs[0].Severity != finding.Medium || fs[0].Fix != fixUFW {
		t.Errorf("firewall.none must be medium with the ufw fix: %+v", fs[0])
	}
}
