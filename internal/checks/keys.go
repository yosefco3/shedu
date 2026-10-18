package checks

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yosefco3/shedu/internal/finding"
	"github.com/yosefco3/shedu/internal/watch"
)

// KeyEntry is one key that can log in to this server.
type KeyEntry struct {
	User        string
	Type        string // ssh-ed25519, ssh-rsa, ...
	Comment     string // the name at the end of the line, often user@host
	Bits        int
	Fingerprint string // SHA256:..., as ssh-keygen -l prints it
	AgeDays     int    // days since the authorized_keys file last changed (keys carry no date)
	LastUse     string // date of the last login with this key, "" if unknown
	File        string
}

// Weak reports keys that can be broken with enough computing power.
func (k KeyEntry) Weak() bool {
	return k.Type == "ssh-dss" || (k.Type == "ssh-rsa" && k.Bits > 0 && k.Bits < 2048)
}

// InventoryKeys lists every authorized key of every account in passwd that
// has a home folder. fsys is the host's /; now dates the files.
func InventoryKeys(fsys fs.FS, passwd io.Reader, now time.Time) ([]KeyEntry, error) {
	var out []KeyEntry
	seen := map[string]bool{}
	sc := bufio.NewScanner(passwd)
	for sc.Scan() {
		f := strings.Split(sc.Text(), ":")
		if len(f) < 7 || f[5] == "" || f[5] == "/" || f[5] == "/nonexistent" {
			continue
		}
		home := strings.TrimPrefix(path.Clean(f[5]), "/")
		for _, name := range []string{"authorized_keys", "authorized_keys2"} {
			p := path.Join(home, ".ssh", name)
			if seen[p] {
				continue
			}
			b, err := fs.ReadFile(fsys, p)
			if err != nil {
				continue
			}
			seen[p] = true
			age := 0
			if info, err := fs.Stat(fsys, p); err == nil {
				age = int(now.Sub(info.ModTime()).Hours() / 24)
			}
			for _, line := range strings.Split(string(b), "\n") {
				if k, ok := parseKeyLine(line); ok {
					k.User, k.AgeDays, k.File = f[0], age, "/"+p
					out = append(out, k)
				}
			}
		}
	}
	return out, sc.Err()
}

// parseKeyLine reads one authorized_keys line, options prefix allowed.
func parseKeyLine(line string) (KeyEntry, bool) {
	fp, comment, ok := watch.Fingerprint(line)
	if !ok {
		return KeyEntry{}, false
	}
	fields := strings.Fields(line)
	for i := 0; i+1 < len(fields); i++ {
		t := fields[i]
		if !(strings.HasPrefix(t, "ssh-") || strings.HasPrefix(t, "ecdsa-") || strings.HasPrefix(t, "sk-")) {
			continue
		}
		blob, err := base64.StdEncoding.DecodeString(fields[i+1])
		if err != nil {
			continue
		}
		return KeyEntry{Type: t, Comment: comment, Bits: keyBits(t, blob), Fingerprint: fp}, true
	}
	return KeyEntry{}, false
}

// keyBits returns the key size. RSA is read from the modulus in the blob.
func keyBits(typ string, blob []byte) int {
	switch {
	case typ == "ssh-ed25519", strings.HasPrefix(typ, "sk-"):
		return 256
	case strings.HasSuffix(typ, "nistp256"):
		return 256
	case strings.HasSuffix(typ, "nistp384"):
		return 384
	case strings.HasSuffix(typ, "nistp521"):
		return 521
	case typ == "ssh-dss":
		return 1024
	case typ == "ssh-rsa":
		// string type, mpint e, mpint n
		var parts [][]byte
		for rest := blob; len(rest) >= 4 && len(parts) < 3; {
			n := binary.BigEndian.Uint32(rest)
			if uint64(len(rest)-4) < uint64(n) {
				return 0
			}
			parts, rest = append(parts, rest[4:4+n]), rest[4+n:]
		}
		if len(parts) == 3 {
			return new(big.Int).SetBytes(parts[2]).BitLen()
		}
	}
	return 0
}

var reKeyLogin = regexp.MustCompile(`Accepted publickey for \S+ from \S+ port \d+ ssh2: \S+ (SHA256:\S+)`)

// LastKeyUse maps fingerprints to the date of their last login, from
// auth.log-style lines in chronological order. ISO timestamps keep the day
// (2026-10-18); classic syslog keeps "Oct 18".
func LastKeyUse(r io.Reader) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		m := reKeyLogin.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		day := ""
		if len(line) >= 10 && line[4] == '-' && line[7] == '-' {
			day = line[:10]
		} else if f := strings.Fields(line); len(f) >= 2 {
			day = f[0] + " " + f[1]
		}
		out[m[1]] = day
	}
	return out
}

// Keys is the "who holds a key" inventory for `shedu check`.
type Keys struct {
	FS     fs.FS // the host's /
	Now    func() time.Time
	IsRoot bool
}

// NewKeys returns the production collector.
func NewKeys() *Keys { return &Keys{FS: os.DirFS("/"), Now: time.Now, IsRoot: os.Geteuid() == 0} }

func (k *Keys) Name() string { return "keys" }

func (k *Keys) Run(ctx context.Context) ([]finding.Finding, error) {
	passwd, err := fs.ReadFile(k.FS, "etc/passwd")
	if err != nil {
		return nil, err
	}
	keys, err := InventoryKeys(k.FS, bytes.NewReader(passwd), k.Now())
	if err != nil {
		return nil, err
	}
	var logs []byte
	for _, name := range []string{"var/log/auth.log.1", "var/log/auth.log"} { // oldest first
		if b, err := fs.ReadFile(k.FS, name); err == nil {
			logs = append(logs, b...)
		}
	}
	used := LastKeyUse(bytes.NewReader(logs))
	sort.SliceStable(keys, func(i, j int) bool { return keys[i].User < keys[j].User })

	var out []finding.Finding
	var lines []string
	anonymous := 0
	for i := range keys {
		key := &keys[i]
		key.LastUse = used[key.Fingerprint]
		name, last := key.Comment, key.LastUse
		if name == "" {
			name = "?"
			anonymous++
		}
		if last == "" {
			last = "—"
		}
		lines = append(lines, fmt.Sprintf("%s · %s %d · %s · %dd · %s", key.User, key.Type, key.Bits, name, key.AgeDays, last))
		if key.Weak() {
			out = append(out, finding.Finding{ID: "keys.weak", Severity: finding.Medium,
				Args: map[string]string{"user": key.User, "type": key.Type, "bits": strconv.Itoa(key.Bits), "comment": key.Comment},
				Fix:  "sudo nano " + key.File + "   # delete the line ending in " + key.Fingerprint, Evidence: key.Fingerprint})
		}
	}
	if len(keys) > 0 {
		out = append(out, finding.Finding{ID: "keys.inventory", Severity: finding.Info,
			Args: map[string]string{"count": strconv.Itoa(len(keys)), "list": strings.Join(lines, "\n")}})
	}
	if anonymous > 0 {
		out = append(out, finding.Finding{ID: "keys.anonymous", Severity: finding.Info,
			Args: map[string]string{"count": strconv.Itoa(anonymous)}})
	}
	if !k.IsRoot {
		out = append(out, finding.Finding{ID: "keys.need_root", Severity: finding.Info})
	}
	return out, nil
}
