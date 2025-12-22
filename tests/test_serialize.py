"""
Tests for serialization
"""

from .context import cryptogenesis


def test_datastream_write_read():
    """Test DataStream write and read operations"""
    stream = cryptogenesis.DataStream()
    data = b"hello world"
    stream.write(data)
    assert stream.size() == len(data)

    read_data = stream.read(len(data))
    assert read_data == data
    assert stream.empty()


def test_datastream_empty():
    """Test DataStream empty check"""
    stream = cryptogenesis.DataStream()
    assert stream.empty()

    stream.write(b"test")
    assert not stream.empty()

    stream.read(4)
    assert stream.empty()


def test_datastream_clear():
    """Test DataStream clear operation"""
    stream = cryptogenesis.DataStream()
    stream.write(b"test")
    stream.clear()
    assert stream.empty()
    assert stream.n_read_pos == 0


def test_datastream_compact():
    """Test DataStream compact operation"""
    stream = cryptogenesis.DataStream()
    stream.write(b"test")
    stream.read(2)
    stream.compact()
    assert stream.n_read_pos == 0
    assert len(stream.vch) == 2


def test_compact_size_encoding():
    """Test compact size encoding"""
    # Small values (< 253)
    stream = bytearray()
    cryptogenesis.write_compact_size(stream, 100)
    assert len(stream) == 1
    value, _ = cryptogenesis.read_compact_size(bytes(stream), 0)
    assert value == 100

    # Medium values (253-65535)
    stream = bytearray()
    cryptogenesis.write_compact_size(stream, 1000)
    assert len(stream) == 3
    value, _ = cryptogenesis.read_compact_size(bytes(stream), 0)
    assert value == 1000

    # Large values (65536-4294967295)
    stream = bytearray()
    cryptogenesis.write_compact_size(stream, 100000)
    assert len(stream) == 5
    value, _ = cryptogenesis.read_compact_size(bytes(stream), 0)
    assert value == 100000

    # Very large values (> 4294967295)
    stream = bytearray()
    cryptogenesis.write_compact_size(stream, 10000000000)
    assert len(stream) == 9
    value, _ = cryptogenesis.read_compact_size(bytes(stream), 0)
    assert value == 10000000000


def test_compact_size_size():
    """Test get_size_of_compact_size"""
    assert cryptogenesis.get_size_of_compact_size(100) == 1
    assert cryptogenesis.get_size_of_compact_size(1000) == 3
    assert cryptogenesis.get_size_of_compact_size(100000) == 5
    assert cryptogenesis.get_size_of_compact_size(10000000000) == 9


def test_serialize_int():
    """Test serialization of integers"""
    stream = cryptogenesis.DataStream()
    stream.serialize(100)
    assert stream.size() == 8  # 64-bit integer

    stream = cryptogenesis.DataStream()
    stream.serialize(-100)
    assert stream.size() == 8


def test_serialize_bytes():
    """Test serialization of bytes"""
    stream = cryptogenesis.DataStream()
    data = b"hello"
    stream.serialize(data)
    assert stream.size() > len(data)  # Includes size prefix


def test_serialize_string():
    """Test serialization of strings"""
    stream = cryptogenesis.DataStream()
    data = "hello"
    stream.serialize(data)
    assert stream.size() > len(data.encode("utf-8"))  # Includes size prefix


def test_serialize_list():
    """Test serialization of lists"""
    stream = cryptogenesis.DataStream()
    data = [1, 2, 3]
    stream.serialize(data)
    assert stream.size() > 0


def test_serialize_uint256():
    """Test serialization of uint256"""
    from cryptogenesis.serialize import serialize_to_stream

    stream = cryptogenesis.DataStream()
    value = cryptogenesis.uint256(100)
    serialize_to_stream(stream, value)
    assert stream.size() == 32  # 256 bits = 32 bytes


def test_unserialize_uint256():
    """Test unserialization of uint256"""
    from cryptogenesis.serialize import serialize_to_stream

    stream = cryptogenesis.DataStream()
    original = cryptogenesis.uint256(100)
    serialize_to_stream(stream, original)

    # uint256 doesn't have unserialize, but we can read bytes directly
    bytes_val = stream.read(32)
    result = cryptogenesis.uint256(bytes_val)
    assert result == original


def test_serialize_transaction():
    """Test serialization of transaction"""
    from cryptogenesis import Script, Transaction, TxIn, TxOut

    tx = Transaction()
    tx.vin = [TxIn()]
    tx.vout = [TxOut(10 * cryptogenesis.COIN, Script())]

    stream = cryptogenesis.DataStream()
    tx.serialize(stream)
    assert stream.size() > 0

    # Unserialize
    tx2 = Transaction()
    stream2 = cryptogenesis.DataStream()
    tx.serialize(stream2)
    tx2.unserialize(stream2)
    assert tx2.version == tx.version
    assert len(tx2.vin) == len(tx.vin)
    assert len(tx2.vout) == len(tx.vout)
