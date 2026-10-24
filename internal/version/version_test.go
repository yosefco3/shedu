package version

import "testing"

func TestNewer(t *testing.T) {
	cases := []struct {
		latest, current string
		want            bool
	}{
		// equal
		{"v0.2.0", "v0.2.0", false},
		{"0.2.0", "v0.2.0", false},
		{"v0.2.0", "0.2.0", false},
		// strictly newer / older
		{"v0.3.0", "v0.2.0", true},
		{"v0.2.1", "v0.2.0", true},
		{"v1.0.0", "v0.9.9", true},
		{"v0.2.0", "v0.3.0", false},
		// numeric, not lexical
		{"v0.10.0", "v0.9.0", true},
		{"v0.9.0", "v0.10.0", false},
		{"v0.2.10", "v0.2.9", true},
		// git describe counts as at least the tag
		{"v0.2.0", "v0.2.0-4-g1a2b3c4", false},
		{"v0.3.0", "v0.2.0-4-g1a2b3c4", true},
		{"v0.2.1", "v0.2.0-4-g1a2b3c4", true},
		{"v0.2.0", "v0.2.0-4-g1a2b3c4-dirty", false},
		{"v0.3.0", "v0.2.0-4-g1a2b3c4-dirty", true},
		{"v0.2.0", "v0.2.0-0-g1a2b3c4-dirty", false},
		{"v0.2.0-4-g1a2b3c4", "v0.2.0", false},
		{"v0.2.0-4-g1a2b3c4", "v0.2.0-4-g1a2b3c4", false},
		{"v0.3.0", "v0.3.0-4-gabc-dirty", false},
		// pre-releases
		{"v0.3.0", "v0.3.0-rc1", true},
		{"v0.3.0-rc1", "v0.3.0", false},
		{"v0.3.0-rc1", "v0.2.9", true},
		{"v0.3.0-rc1", "v0.2.0-4-gabc1234", true},
		{"v0.3.0-rc1", "v0.3.0-rc1", false},
		{"v0.2.0", "v0.3.0-rc1", false},
		// unparsable input never nudges
		{"v0.2.0", "dev", false},
		{"v0.2.0", "", false},
		{"", "v0.2.0", false},
		{"", "", false},
		{"garbage", "v0.2.0", false},
		{"v0.2.0", "garbage", false},
		{"dev", "dev", false},
		{"v1.2", "v1.0.0", false},
		{"v1.2.3.4", "v1.0.0", false},
		{"v1.x.0", "v0.1.0", false},
		{"v-1.2.0", "v0.1.0", false},
		{"v1.2.3-", "v0.1.0", false},
	}
	for _, c := range cases {
		if got := Newer(c.latest, c.current); got != c.want {
			t.Errorf("Newer(%q, %q) = %v, want %v", c.latest, c.current, got, c.want)
		}
	}
}
