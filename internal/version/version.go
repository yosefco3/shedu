// Package version compares shedu release versions.
package version

import (
	"strconv"
	"strings"
)

// parsed is a version reduced to what ordering needs.
type parsed struct {
	nums [3]int // MAJOR, MINOR, PATCH
	pre  bool   // a pre-release (vX.Y.Z-rc1): older than the release vX.Y.Z
}

// parse reads "v1.2.3", "1.2.3", "v1.2.3-rc1", "v1.2.3-4-gabc1234" and
// "v1.2.3-4-gabc1234-dirty". A git-describe build (N commits after a tag) counts as the
// tagged release, never as a pre-release of it, so it is at least X.Y.Z.
func parse(s string) (parsed, bool) {
	var p parsed
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	core, rest, hasRest := strings.Cut(s, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return p, false
	}
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 || part == "" || part[0] == '+' {
			return p, false
		}
		p.nums[i] = n
	}
	if hasRest {
		if rest == "" {
			return p, false
		}
		p.pre = !isDescribe(rest)
	}
	return p, true
}

// isDescribe reports whether s (what follows "vX.Y.Z-") is "N-gHASH" or "N-gHASH-dirty".
func isDescribe(s string) bool {
	s = strings.TrimSuffix(s, "-dirty")
	n, hash, ok := strings.Cut(s, "-g")
	if !ok || hash == "" {
		return false
	}
	if _, err := strconv.Atoi(n); err != nil {
		return false
	}
	for _, c := range hash {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Newer reports whether latest is strictly newer than current. It is false whenever
// either string does not parse (a "dev" build, an empty string, garbage), so a build of
// unknown version is never nudged to upgrade.
func Newer(latest, current string) bool {
	l, ok := parse(latest)
	if !ok {
		return false
	}
	c, ok := parse(current)
	if !ok {
		return false
	}
	for i := range l.nums {
		if l.nums[i] != c.nums[i] {
			return l.nums[i] > c.nums[i]
		}
	}
	// Same X.Y.Z: a release beats a pre-release of itself; nothing else is newer.
	return !l.pre && c.pre
}
