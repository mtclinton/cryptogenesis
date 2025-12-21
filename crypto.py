"""
Copyright (c) 2009 Satoshi Nakamoto
Distributed under the MIT/X11 software license

Cryptographic functions: SHA256, RIPEMD160, ECDSA
"""

import hashlib
from typing import Optional

from uint256 import uint256


def sha256(data: bytes) -> bytes:
    """Single SHA256 hash"""
    return hashlib.sha256(data).digest()


def double_sha256(data: bytes) -> bytes:
    """Double SHA256 hash (Bitcoin hash)"""
    return sha256(sha256(data))


def ripemd160(data: bytes) -> bytes:
    """RIPEMD160 hash"""
    try:
        import hashlib

        # Try using hashlib's ripemd160 if available
        h = hashlib.new("ripemd160")
        h.update(data)
        return h.digest()
    except (ValueError, OSError):
        # Fallback: use pure Python implementation if needed
        # For now, we'll use a placeholder - in production you'd want a proper implementation
        raise NotImplementedError(
            "RIPEMD160 not available. Install OpenSSL or use a library that provides RIPEMD160"
        )


def hash160(data: bytes) -> bytes:
    """SHA256 followed by RIPEMD160"""
    return ripemd160(sha256(data))


def hash256(data: bytes) -> bytes:
    """Double SHA256"""
    return double_sha256(data)


def hash_to_uint256(data: bytes) -> uint256:
    """Convert hash bytes to uint256"""
    if len(data) != 32:
        raise ValueError("Hash must be 32 bytes")
    return uint256(data)


def serialize_hash(obj) -> uint256:
    """Serialize object and hash it"""
    from serialize import DataStream

    stream = DataStream()
    stream.serialize(obj)
    return hash_to_uint256(double_sha256(stream.get_bytes()))


# ECDSA key management
try:
    from ecdsa import BadSignatureError, SECP256k1, SigningKey, VerifyingKey
    from ecdsa.util import sigdecode_der, sigencode_der

    ECDSA_AVAILABLE = True
except ImportError:
    ECDSA_AVAILABLE = False
    print("Warning: ecdsa library not available. Install with: pip install ecdsa")


class Key:
    """ECDSA key for Bitcoin"""

    def __init__(self):
        if not ECDSA_AVAILABLE:
            raise RuntimeError("ECDSA library not available")
        self._key = None
        self._pubkey = None

    def generate_new_key(self):
        """Generate a new key pair"""
        if not ECDSA_AVAILABLE:
            raise RuntimeError("ECDSA library not available")
        self._key = SigningKey.generate(curve=SECP256k1)
        self._pubkey = self._key.get_verifying_key()

    @property
    def public_key(self) -> bytes:
        """Public key as property"""
        return self.get_pubkey()

    @property
    def private_key(self) -> bytes:
        """Private key as property"""
        return self.get_privkey()

    def get_pubkey(self) -> bytes:
        """Get public key as bytes"""
        if self._pubkey is None:
            raise ValueError("No public key")
        # Bitcoin uses uncompressed public keys (65 bytes: 0x04 + 64 bytes)
        return b"\x04" + self._pubkey.to_string()

    def get_privkey(self) -> bytes:
        """Get private key as bytes"""
        if self._key is None:
            raise ValueError("No private key")
        return self._key.to_string()

    def set_privkey(self, privkey: bytes) -> bool:
        """Set private key from bytes"""
        if not ECDSA_AVAILABLE:
            return False
        try:
            self._key = SigningKey.from_string(privkey, curve=SECP256k1)
            self._pubkey = self._key.get_verifying_key()
            return True
        except Exception:
            return False

    def set_pubkey(self, pubkey: bytes) -> bool:
        """Set public key from bytes"""
        if not ECDSA_AVAILABLE:
            return False
        try:
            if len(pubkey) == 65 and pubkey[0] == 0x04:
                # Uncompressed public key
                self._pubkey = VerifyingKey.from_string(pubkey[1:], curve=SECP256k1)
                return True
        except Exception:
            pass
        return False

    def sign(self, hash_value: uint256) -> bytes:
        """Sign a hash"""
        if self._key is None:
            raise ValueError("No private key")
        hash_bytes = hash_value.to_bytes()
        sig = self._key.sign(hash_bytes, sigencode=sigencode_der)
        return sig

    def verify(self, hash_value: uint256, sig: bytes) -> bool:
        """Verify a signature"""
        if self._pubkey is None:
            return False
        try:
            hash_bytes = hash_value.to_bytes()
            self._pubkey.verify(sig, hash_bytes, sigdecode=sigdecode_der)
            return True
        except BadSignatureError:
            return False

    @staticmethod
    def sign_static(privkey: bytes, hash_value: uint256) -> Optional[bytes]:
        """Static method to sign with private key"""
        try:
            key = SigningKey.from_string(privkey, curve=SECP256k1)
            hash_bytes = hash_value.to_bytes()
            return key.sign(hash_bytes, sigencode=sigencode_der)
        except Exception:
            return None

    @staticmethod
    def verify_static(pubkey: bytes, hash_value: uint256, sig: bytes) -> bool:
        """Static method to verify signature"""
        try:
            if len(pubkey) == 65 and pubkey[0] == 0x04:
                vk = VerifyingKey.from_string(pubkey[1:], curve=SECP256k1)
                hash_bytes = hash_value.to_bytes()
                vk.verify(sig, hash_bytes, sigdecode=sigdecode_der)
                return True
        except Exception:
            pass
        return False
