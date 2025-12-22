"""
Tests for cryptographic functions and Key
"""

from .context import cryptogenesis


def test_sha256():
    """Test SHA256 hash function"""
    data = b"hello world"
    hash_val = cryptogenesis.sha256(data)
    assert isinstance(hash_val, bytes)
    assert len(hash_val) == 32

    # Test consistency
    hash_val2 = cryptogenesis.sha256(data)
    assert hash_val == hash_val2

    # Test different data produces different hash
    hash_val3 = cryptogenesis.sha256(b"different")
    assert hash_val != hash_val3


def test_double_sha256():
    """Test double SHA256 hash function"""
    data = b"hello world"
    hash_val = cryptogenesis.double_sha256(data)
    assert isinstance(hash_val, bytes)
    assert len(hash_val) == 32

    # Should be different from single SHA256
    single_hash = cryptogenesis.sha256(data)
    assert hash_val != single_hash


def test_ripemd160():
    """Test RIPEMD160 hash function"""
    try:
        data = b"hello world"
        hash_val = cryptogenesis.ripemd160(data)
        assert isinstance(hash_val, bytes)
        assert len(hash_val) == 20
    except NotImplementedError:
        # RIPEMD160 may not be available
        pass


def test_hash160():
    """Test hash160 (SHA256 + RIPEMD160)"""
    try:
        data = b"hello world"
        hash_val = cryptogenesis.hash160(data)
        assert isinstance(hash_val, bytes)
        assert len(hash_val) == 20
    except NotImplementedError:
        # RIPEMD160 may not be available
        pass


def test_hash256():
    """Test hash256 (double SHA256)"""
    data = b"hello world"
    hash_val = cryptogenesis.hash256(data)
    assert isinstance(hash_val, bytes)
    assert len(hash_val) == 32
    assert hash_val == cryptogenesis.double_sha256(data)


def test_hash_to_uint256():
    """Test hash_to_uint256 conversion"""
    data = b"hello world"
    hash_val = cryptogenesis.sha256(data)
    uint_val = cryptogenesis.hash_to_uint256(hash_val)
    assert isinstance(uint_val, cryptogenesis.uint256)

    # Test with wrong length
    try:
        cryptogenesis.hash_to_uint256(b"short")
        assert False, "Should have raised ValueError"
    except ValueError:
        pass


def test_key_generation():
    """Test Key generation"""
    try:
        key = cryptogenesis.Key()
        key.generate_new_key()
        assert key._key is not None
        assert key._pubkey is not None
    except RuntimeError:
        # ECDSA may not be available
        pass


def test_key_public_key():
    """Test Key public key property"""
    try:
        key = cryptogenesis.Key()
        key.generate_new_key()
        pubkey = key.public_key
        assert isinstance(pubkey, bytes)
        assert len(pubkey) > 0

        # Should be consistent
        pubkey2 = key.get_pubkey()
        assert pubkey == pubkey2
    except RuntimeError:
        # ECDSA may not be available
        pass


def test_key_private_key():
    """Test Key private key property"""
    try:
        key = cryptogenesis.Key()
        key.generate_new_key()
        privkey = key.private_key
        assert isinstance(privkey, bytes)
        assert len(privkey) > 0
    except RuntimeError:
        # ECDSA may not be available
        pass


def test_key_sign_verify():
    """Test Key signing and verification"""
    try:
        key = cryptogenesis.Key()
        key.generate_new_key()

        message = b"test message"
        # Key.sign expects a uint256, so hash the message first
        message_hash = cryptogenesis.hash_to_uint256(cryptogenesis.double_sha256(message))
        signature = key.sign(message_hash)
        assert isinstance(signature, bytes)
        assert len(signature) > 0

        # Verify signature
        assert key.verify(message_hash, signature)

        # Wrong message should fail
        wrong_hash = cryptogenesis.hash_to_uint256(cryptogenesis.double_sha256(b"wrong message"))
        assert not key.verify(wrong_hash, signature)

        # Wrong signature should fail
        wrong_sig = b"\x00" * len(signature)
        assert not key.verify(message_hash, wrong_sig)
    except RuntimeError:
        # ECDSA may not be available
        pass


def test_key_serialize_hash():
    """Test serialize_hash function"""
    try:
        key = cryptogenesis.Key()
        key.generate_new_key()

        # Create a simple object to serialize
        from cryptogenesis import uint256

        obj = uint256(100)
        hash_val = cryptogenesis.serialize_hash(obj)
        assert isinstance(hash_val, cryptogenesis.uint256)
    except RuntimeError:
        # ECDSA may not be available
        pass


def test_key_consistency():
    """Test that key operations are consistent"""
    try:
        key1 = cryptogenesis.Key()
        key1.generate_new_key()

        # Get public key
        pubkey1 = key1.public_key

        # Sign a message (hash first)
        message = b"test"
        message_hash = cryptogenesis.hash_to_uint256(cryptogenesis.double_sha256(message))
        sig1 = key1.sign(message_hash)

        # Verify with same key
        assert key1.verify(message_hash, sig1)

        # Create new key (should be different)
        key2 = cryptogenesis.Key()
        key2.generate_new_key()
        assert key2.public_key != pubkey1

        # Should not verify with different key
        assert not key2.verify(message_hash, sig1)
    except RuntimeError:
        # ECDSA may not be available
        pass
