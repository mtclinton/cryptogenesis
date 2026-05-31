"""
Phase 1 pins for ECDSA signing (crypto.py).

The signer must sign the raw 32-byte sighash directly (sign_digest), not
re-hash it with the library default SHA-1. These tests verify a round-trip,
rejection of a tampered digest, and crucially that a signature is NOT valid
over sha1(sighash) -- which is what the old buggy path produced.
"""

import hashlib

import pytest

from .context import cryptogenesis  # noqa: F401

try:
    from cryptogenesis.crypto import Key

    from ecdsa import SECP256k1, VerifyingKey, util

    ECDSA = True
except Exception:  # pragma: no cover - exercised only when ecdsa is absent
    ECDSA = False

pytestmark = pytest.mark.skipif(not ECDSA, reason="ecdsa library not installed")

uint256 = cryptogenesis.uint256


def _digest(msg: bytes) -> uint256:
    return uint256(hashlib.sha256(msg).digest())


def test_sign_verify_round_trip():
    key = Key()
    key.generate_new_key()
    h = _digest(b"cryptogenesis sighash")
    sig = key.sign(h)
    assert key.verify(h, sig) is True


def test_tampered_digest_fails():
    key = Key()
    key.generate_new_key()
    sig = key.sign(_digest(b"original"))
    assert key.verify(_digest(b"tampered"), sig) is False


def test_signature_is_over_raw_digest_not_sha1():
    # Sign the raw sighash, then confirm at the library level that the signature
    # verifies over the raw 32 bytes and NOT over sha1(sighash) (the old bug).
    key = Key()
    key.generate_new_key()
    h = _digest(b"no sha1 re-hash")
    raw = h.to_bytes()
    sig = key.sign(h)

    vk = VerifyingKey.from_string(key.get_pubkey()[1:], curve=SECP256k1)
    assert vk.verify_digest(sig, raw, sigdecode=util.sigdecode_der) is True

    with pytest.raises(Exception):
        vk.verify_digest(sig, hashlib.sha1(raw).digest(), sigdecode=util.sigdecode_der)
