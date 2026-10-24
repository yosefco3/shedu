#!/usr/bin/env python3
"""Regenerate the minisign test fixtures in this folder (needs PyNaCl: apt install python3-nacl).

TEST KEYS ONLY. The keys are derived from fixed, public seeds, so they protect nothing and the
output is byte-for-byte reproducible. The real release key never goes near this script.

Files written:
  test.pub, other.pub                 minisign public keys (test key, and an unrelated key)
  shedu_linux_amd64, shedu_linux_arm64  tiny stand-in "binaries" (shell scripts printing v0.3.1)
  SHA256SUMS                          sha256sum output for both
  SHA256SUMS.minisig                  prehashed ("ED", minisign's default) signature by test key
  SHA256SUMS.legacy.minisig           legacy ("Ed") signature by test key
  SHA256SUMS.otherkey.minisig         valid signature by other key (must be rejected)
  SHA256SUMS.rc1.minisig              test key, trusted comment "shedu v0.3.1-rc1 SHA256SUMS"
  SHA256SUMS.suffix.minisig           test key, trusted comment with extra text (must be rejected)

With the real minisign tool instead (keys would then be random, not reproducible):
  minisign -G -W -p test.pub -s test.key
  minisign -S -s test.key -m SHA256SUMS -x SHA256SUMS.minisig -t "shedu v0.3.1 SHA256SUMS"
  minisign -Vm SHA256SUMS -x SHA256SUMS.minisig -p test.pub
"""
import base64, hashlib, os
from nacl.signing import SigningKey

HERE = os.path.dirname(os.path.abspath(__file__))
TRUSTED = b"shedu v0.3.1 SHA256SUMS"


def key(name):
    seed = hashlib.sha256(b"shedu minisign TEST key, public seed: " + name.encode()).digest()
    sk = SigningKey(seed)
    keyid = hashlib.sha256(b"keyid " + name.encode()).digest()[:8]
    return sk, keyid


def write(name, data):
    with open(os.path.join(HERE, name), "wb") as f:
        f.write(data)


def pub(sk, keyid):
    ident = int.from_bytes(keyid, "little")
    b64 = base64.b64encode(b"Ed" + keyid + bytes(sk.verify_key)).decode()
    return f"untrusted comment: minisign public key {ident:016X}\n{b64}\n".encode()


def sig(sk, keyid, msg, prehashed=True, trusted=TRUSTED):
    alg = b"ED" if prehashed else b"Ed"
    signed = hashlib.blake2b(msg, digest_size=64).digest() if prehashed else msg
    s = sk.sign(signed).signature
    glob = sk.sign(s + trusted).signature
    return (b"untrusted comment: signature from minisign secret key\n"
            + base64.b64encode(alg + keyid + s) + b"\n"
            + b"trusted comment: " + trusted + b"\n"
            + base64.b64encode(glob) + b"\n")


test, other = key("test"), key("other")
write("test.pub", pub(*test))
write("other.pub", pub(*other))
sums = b""
for arch in ("amd64", "arm64"):
    body = b"#!/bin/sh\necho v0.3.1\n"
    write("shedu_linux_" + arch, body)
    sums += hashlib.sha256(body).hexdigest().encode() + b"  shedu_linux_" + arch.encode() + b"\n"
write("SHA256SUMS", sums)
write("SHA256SUMS.minisig", sig(*test, sums))
write("SHA256SUMS.legacy.minisig", sig(*test, sums, prehashed=False))
write("SHA256SUMS.otherkey.minisig", sig(*other, sums))
write("SHA256SUMS.rc1.minisig", sig(*test, sums, trusted=b"shedu v0.3.1-rc1 SHA256SUMS"))
write("SHA256SUMS.suffix.minisig", sig(*test, sums, trusted=b"shedu v0.3.1 SHA256SUMS and more"))
