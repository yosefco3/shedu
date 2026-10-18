package checks

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/yosefco3/shedu/internal/finding"
)

func sshString(b []byte) []byte {
	out := make([]byte, 4, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	return append(out, b...)
}

func keyLine(typ string, body []byte, comment string) string {
	blob := append(sshString([]byte(typ)), body...)
	return strings.TrimSpace(typ + " " + base64.StdEncoding.EncodeToString(blob) + " " + comment)
}

func rsaBody(bits int) []byte {
	n := make([]byte, bits/8+1) // leading 0x00 keeps the mpint positive
	n[1] = 0x80
	return append(sshString([]byte{0x01, 0x00, 0x01}), sshString(n)...)
}

func TestKeyBits(t *testing.T) {
	for _, bits := range []int{1024, 2048, 4096} {
		k, ok := parseKeyLine(keyLine("ssh-rsa", rsaBody(bits), "x"))
		if !ok || k.Bits != bits {
			t.Errorf("rsa %d: %+v %v", bits, k, ok)
		}
	}
	k, ok := parseKeyLine(`from="10.0.0.0/8",no-pty ` + keyLine("ssh-ed25519", sshString(make([]byte, 32)), "ci@runner"))
	if !ok || k.Bits != 256 || k.Comment != "ci@runner" || !strings.HasPrefix(k.Fingerprint, "SHA256:") {
		t.Errorf("ed25519 with options: %+v", k)
	}
}

func TestKeysInventory(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	ed := keyLine("ssh-ed25519", sshString(make([]byte, 32)), "yosef@laptop")
	weak := keyLine("ssh-rsa", rsaBody(1024), "")
	edKey, _ := parseKeyLine(ed)
	fsys := fstest.MapFS{
		"etc/passwd": {Data: []byte("root:x:0:0:root:/root:/bin/bash\nyosef:x:1000:1000::/home/yosef:/bin/bash\n" +
			"deploy:x:1001:1001::/home/deploy:/bin/bash\nnobody:x:65534:65534::/nonexistent:/usr/sbin/nologin\n")},
		"home/yosef/.ssh/authorized_keys":  {Data: []byte("# my laptop\n" + ed + "\n"), ModTime: now.Add(-12 * 24 * time.Hour)},
		"home/deploy/.ssh/authorized_keys": {Data: []byte(weak + "\n" + ed + "\n"), ModTime: now.Add(-400 * 24 * time.Hour)},
		"var/log/auth.log": {Data: []byte("2026-10-17T09:15:02.123+03:00 host sshd[1]: Accepted publickey for yosef from 10.0.0.2 port 5 ssh2: ED25519 " +
			edKey.Fingerprint + "\n")},
	}
	fs, err := (&Keys{FS: fsys, Now: func() time.Time { return now }, IsRoot: true}).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var inv, weakF, anon *finding.Finding
	for i := range fs {
		switch fs[i].ID {
		case "keys.inventory":
			inv = &fs[i]
		case "keys.weak":
			weakF = &fs[i]
		case "keys.anonymous":
			anon = &fs[i]
		}
	}
	if inv == nil || inv.Args["count"] != "3" {
		t.Fatalf("inventory: %+v", fs)
	}
	want := "deploy · ssh-rsa 1024 · ? · 400d · —\n" +
		"deploy · ssh-ed25519 256 · yosef@laptop · 400d · 2026-10-17\n" +
		"yosef · ssh-ed25519 256 · yosef@laptop · 12d · 2026-10-17"
	if inv.Args["list"] != want {
		t.Errorf("list:\n%s\nwant\n%s", inv.Args["list"], want)
	}
	if weakF == nil || weakF.Severity != finding.Medium || weakF.Args["user"] != "deploy" || !strings.HasPrefix(weakF.Fix, "sudo nano /home/deploy/.ssh/authorized_keys") {
		t.Errorf("weak: %+v", weakF)
	}
	if anon == nil || anon.Args["count"] != "1" {
		t.Errorf("anonymous: %+v", anon)
	}
}

func TestLastKeyUseSyslog(t *testing.T) {
	m := LastKeyUse(strings.NewReader("Oct  3 08:00:00 h sshd[9]: Accepted publickey for a from 1.2.3.4 port 22 ssh2: RSA SHA256:abc\n" +
		"Oct 18 10:00:00 h sshd[9]: Accepted publickey for a from 1.2.3.4 port 22 ssh2: RSA SHA256:abc\n"))
	if m["SHA256:abc"] != "Oct 18" {
		t.Errorf("got %v", m)
	}
}
