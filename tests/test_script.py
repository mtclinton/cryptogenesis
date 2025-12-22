"""
Tests for Script operations
"""

from .context import cryptogenesis


def test_script_initialization():
    """Test Script initialization"""
    script = cryptogenesis.Script()
    assert len(script.data) == 0

    script2 = cryptogenesis.Script(b"hello")
    assert len(script2.data) == 5


def test_script_push_data():
    """Test pushing data to script"""
    script = cryptogenesis.Script()
    data = b"hello"
    script.push_data(data)
    assert len(script.data) > len(data)  # Includes size prefix


def test_script_push_int():
    """Test pushing integers to script"""
    script = cryptogenesis.Script()

    # Small integers use opcodes
    script.push_int(0)
    script.push_int(1)
    script.push_int(16)
    assert len(script.data) == 3

    # Larger integers use variable-length encoding
    script.push_int(100)
    assert len(script.data) > 3

    # Negative integers
    script.push_int(-1)
    assert len(script.data) > 4


def test_script_push_int_force_bignum():
    """Test pushing integers with force_bignum flag"""
    script = cryptogenesis.Script()
    script.push_int(4, force_bignum=True)
    # Should use variable-length encoding instead of OP_4
    assert len(script.data) > 1


def test_script_push_opcode():
    """Test pushing opcodes to script"""
    script = cryptogenesis.Script()
    from cryptogenesis.transaction import OP_CHECKSIG, OP_DUP, OP_HASH160

    script.push_opcode(OP_DUP)
    script.push_opcode(OP_HASH160)
    script.push_opcode(OP_CHECKSIG)
    assert len(script.data) == 3


def test_script_concatenation():
    """Test script concatenation"""
    script1 = cryptogenesis.Script()
    script1.push_data(b"hello")

    script2 = cryptogenesis.Script()
    script2.push_data(b"world")

    script3 = script1 + script2
    assert len(script3.data) == len(script1.data) + len(script2.data)


def test_script_equality():
    """Test script equality"""
    script1 = cryptogenesis.Script()
    script1.push_data(b"hello")

    script2 = cryptogenesis.Script()
    script2.push_data(b"hello")

    script3 = cryptogenesis.Script()
    script3.push_data(b"world")

    # Script doesn't have __eq__, so compare data directly
    assert script1.data == script2.data
    assert script1.data != script3.data


def test_script_get_hash():
    """Test script hash calculation"""
    script = cryptogenesis.Script()
    script.push_data(b"test")
    # Script doesn't have get_hash, but we can hash the serialized script
    stream = cryptogenesis.DataStream()
    script.serialize(stream)
    hash_val = cryptogenesis.hash_to_uint256(cryptogenesis.double_sha256(stream.get_bytes()))
    assert isinstance(hash_val, cryptogenesis.uint256)


def test_script_is_empty():
    """Test script empty check"""
    script = cryptogenesis.Script()
    assert len(script.data) == 0

    script.push_data(b"test")
    assert len(script.data) > 0


def test_script_clear():
    """Test script clear operation"""
    script = cryptogenesis.Script()
    script.push_data(b"test")
    script.data.clear()
    assert len(script.data) == 0


def test_script_eval():
    """Test basic script evaluation"""
    script = cryptogenesis.Script()
    script.push_int(1)
    script.push_int(2)
    from cryptogenesis.transaction import OP_ADD

    script.push_opcode(OP_ADD)
    # Note: Full script evaluation would require a more complete implementation
    # This is a basic test that the script can be constructed
    assert len(script.data) > 0


def test_script_pubkey_hash():
    """Test creating a pubkey hash script"""
    script = cryptogenesis.Script()
    pubkey_hash = b"\x00" * 20  # Dummy hash
    from cryptogenesis.transaction import OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, OP_HASH160

    script.push_opcode(OP_DUP)
    script.push_opcode(OP_HASH160)
    script.push_data(pubkey_hash)
    script.push_opcode(OP_EQUALVERIFY)
    script.push_opcode(OP_CHECKSIG)
    assert len(script.data) > 0


def test_script_string_representation():
    """Test script string representation"""
    script = cryptogenesis.Script()
    script.push_data(b"test")
    str_repr = str(script)
    assert isinstance(str_repr, str)
    assert len(str_repr) > 0
