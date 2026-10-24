package update

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// ErrSignatureInvalid means the signature does not match the file or the key. The
// download is then treated as hostile: nothing is installed.
var ErrSignatureInvalid = errors.New("signature invalid")

// PublicKey is a minisign public key: an Ed25519 key and its 8-byte key id.
type PublicKey struct {
	ID  [8]byte
	Key ed25519.PublicKey
}

// ParsePublicKey reads a minisign public key, either the whole minisign.pub file
// ("untrusted comment: ..." and a base64 line) or only the base64 line ("RW...").
func ParsePublicKey(s string) (PublicKey, error) {
	var pk PublicKey
	line := ""
	for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "untrusted comment:") {
			line = l
			break
		}
	}
	raw, err := base64.StdEncoding.DecodeString(line)
	if err != nil || len(raw) != 2+8+ed25519.PublicKeySize || string(raw[:2]) != "Ed" {
		return pk, errors.New("not a minisign public key")
	}
	copy(pk.ID[:], raw[2:10])
	pk.Key = ed25519.PublicKey(raw[10:])
	return pk, nil
}

// Signature is a parsed .minisig file.
type Signature struct {
	Prehashed      bool // "ED": signs BLAKE2b-512(file), minisign's default; "Ed": signs the file
	KeyID          [8]byte
	Sig            []byte
	TrustedComment string
	GlobalSig      []byte // signs Sig || TrustedComment
}

// ParseSignature reads a .minisig file: an untrusted comment, the signature line, a
// "trusted comment:" line and the global signature line.
func ParseSignature(b []byte) (Signature, error) {
	var s Signature
	lines := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	if len(lines) < 4 || !strings.HasPrefix(lines[0], "untrusted comment:") {
		return s, errors.New("not a minisign signature")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[1]))
	if err != nil || len(raw) != 2+8+ed25519.SignatureSize {
		return s, errors.New("not a minisign signature")
	}
	switch string(raw[:2]) {
	case "ED":
		s.Prehashed = true
	case "Ed":
	default:
		return s, fmt.Errorf("unknown minisign signature algorithm %q", raw[:2])
	}
	copy(s.KeyID[:], raw[2:10])
	s.Sig = raw[10:]
	tc, ok := strings.CutPrefix(lines[2], "trusted comment: ")
	if !ok {
		return s, errors.New("minisign signature has no trusted comment")
	}
	s.TrustedComment = tc
	s.GlobalSig, err = base64.StdEncoding.DecodeString(strings.TrimSpace(lines[3]))
	if err != nil || len(s.GlobalSig) != ed25519.SignatureSize {
		return s, errors.New("minisign signature has a broken trusted-comment signature")
	}
	return s, nil
}

// VerifyMinisign checks msg against sig with pk, the way `minisign -V` does: the key ids
// must match, the file signature must hold, and so must the signature over the trusted
// comment (so the comment, which names the release, cannot be swapped either).
func VerifyMinisign(pk PublicKey, msg, sigFile []byte) (Signature, error) {
	s, err := ParseSignature(sigFile)
	if err != nil {
		return s, err
	}
	if s.KeyID != pk.ID {
		return s, fmt.Errorf("%w: signed by a different key (%X, expected %X)", ErrSignatureInvalid, s.KeyID, pk.ID)
	}
	signed := msg
	if s.Prehashed {
		h := blake2b512(msg)
		signed = h[:]
	}
	if !ed25519.Verify(pk.Key, signed, s.Sig) {
		return s, ErrSignatureInvalid
	}
	global := append(bytes.Clone(s.Sig), s.TrustedComment...)
	if !ed25519.Verify(pk.Key, global, s.GlobalSig) {
		return s, fmt.Errorf("%w: trusted comment was changed", ErrSignatureInvalid)
	}
	return s, nil
}
