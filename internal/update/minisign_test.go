package update

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

// Fixtures: testdata/release, made by regen.py (fixed public test seeds, never a real key).

func readFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/release/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func testKey(t *testing.T, name string) PublicKey {
	t.Helper()
	pk, err := ParsePublicKey(string(readFile(t, name)))
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

func TestParsePublicKeyFileAndBareLine(t *testing.T) {
	file := string(readFile(t, "test.pub"))
	a, err := ParsePublicKey(file)
	if err != nil {
		t.Fatal(err)
	}
	bare := strings.Split(strings.TrimSpace(file), "\n")[1]
	if !strings.HasPrefix(bare, "RW") {
		t.Fatalf("minisign keys start with RW: %q", bare)
	}
	b, err := ParsePublicKey(bare)
	if err != nil || a.ID != b.ID || !a.Key.Equal(b.Key) {
		t.Fatalf("bare line parsed differently: %v", err)
	}
	for _, bad := range []string{"", "REPLACE_WITH_MINISIGN_PUBLIC_KEY", "RWQ=", "untrusted comment: x\n"} {
		if _, err := ParsePublicKey(bad); err == nil {
			t.Errorf("%q: accepted", bad)
		}
	}
}

func TestVerifyMinisignBothFormats(t *testing.T) {
	pk := testKey(t, "test.pub")
	sums := readFile(t, "SHA256SUMS")
	for _, name := range []string{"SHA256SUMS.minisig", "SHA256SUMS.legacy.minisig"} {
		s, err := VerifyMinisign(pk, sums, readFile(t, name))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if s.TrustedComment != "shedu v0.3.1 SHA256SUMS" {
			t.Errorf("%s: trusted comment %q", name, s.TrustedComment)
		}
	}
}

func TestVerifyMinisignRejects(t *testing.T) {
	pk := testKey(t, "test.pub")
	sums := readFile(t, "SHA256SUMS")
	sig := readFile(t, "SHA256SUMS.minisig")

	if _, err := VerifyMinisign(pk, append(bytes.Clone(sums), '\n'), sig); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("changed file: %v", err)
	}
	if _, err := VerifyMinisign(pk, sums, readFile(t, "SHA256SUMS.otherkey.minisig")); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("other key's signature: %v", err)
	}
	// The other key with a forged key id: the key id matches, the math does not.
	other := testKey(t, "other.pub")
	other.ID = pk.ID
	if _, err := VerifyMinisign(other, sums, sig); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("wrong key, same id: %v", err)
	}
	// A swapped trusted comment (e.g. to pass an old release off as a new one).
	swapped := bytes.Replace(sig, []byte("shedu v0.3.1"), []byte("shedu v9.9.9"), 1)
	if _, err := VerifyMinisign(pk, sums, swapped); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("swapped trusted comment: %v", err)
	}
	for _, junk := range [][]byte{nil, []byte("hello"), sig[:60]} {
		if _, err := VerifyMinisign(pk, sums, junk); err == nil {
			t.Errorf("junk %q accepted", junk)
		}
	}
}
