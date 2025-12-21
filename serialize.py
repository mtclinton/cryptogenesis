"""
Copyright (c) 2009 Satoshi Nakamoto
Distributed under the MIT/X11 software license

Serialization system for Bitcoin protocol
"""

import struct
from typing import Any, Tuple

VERSION = 101

# Serialization flags
SER_NETWORK = 1 << 0
SER_DISK = 1 << 1
SER_GETHASH = 1 << 2
SER_SKIPSIG = 1 << 16
SER_BLOCKHEADERONLY = 1 << 17


def get_size_of_compact_size(n_size: int) -> int:
    """Get size of compact size encoding"""
    if n_size < 253:
        return 1
    elif n_size <= 0xFFFF:
        return 3
    elif n_size <= 0xFFFFFFFF:
        return 5
    else:
        return 9


def write_compact_size(stream: bytearray, n_size: int):
    """Write compact size to stream"""
    if n_size < 253:
        stream.extend(struct.pack("<B", n_size))
    elif n_size <= 0xFFFF:
        stream.extend(struct.pack("<BH", 253, n_size))
    elif n_size <= 0xFFFFFFFF:
        stream.extend(struct.pack("<BI", 254, n_size))
    else:
        stream.extend(struct.pack("<BQ", 255, n_size))


def read_compact_size(data: bytes, offset: int) -> Tuple[int, int]:
    """Read compact size from data, returns (value, bytes_read)"""
    if offset >= len(data):
        raise ValueError("End of data")

    ch_size = data[offset]
    offset += 1

    if ch_size < 253:
        return ch_size, offset
    elif ch_size == 253:
        if offset + 2 > len(data):
            raise ValueError("End of data")
        n_size = struct.unpack("<H", data[offset : offset + 2])[0]
        return n_size, offset + 2
    elif ch_size == 254:
        if offset + 4 > len(data):
            raise ValueError("End of data")
        n_size = struct.unpack("<I", data[offset : offset + 4])[0]
        return n_size, offset + 4
    else:  # 255
        if offset + 8 > len(data):
            raise ValueError("End of data")
        n_size = struct.unpack("<Q", data[offset : offset + 8])[0]
        return n_size, offset + 8


class DataStream:
    """Data stream for serialization"""

    def __init__(self, stream_type: int = 0, version: int = VERSION):
        self.vch = bytearray()
        self.n_read_pos = 0
        self.n_type = stream_type
        self.n_version = version

    def write(self, data: bytes):
        """Write data to stream"""
        self.vch.extend(data)

    def read(self, n_size: int) -> bytes:
        """Read data from stream"""
        if self.n_read_pos + n_size > len(self.vch):
            raise ValueError("End of data")
        result = bytes(self.vch[self.n_read_pos : self.n_read_pos + n_size])
        self.n_read_pos += n_size
        return result

    def size(self) -> int:
        """Get remaining size"""
        return len(self.vch) - self.n_read_pos

    def empty(self) -> bool:
        """Check if stream is empty"""
        return self.n_read_pos >= len(self.vch)

    def clear(self):
        """Clear stream"""
        self.vch.clear()
        self.n_read_pos = 0

    def compact(self):
        """Compact stream by removing read data"""
        if self.n_read_pos > 0:
            self.vch = self.vch[self.n_read_pos :]
            self.n_read_pos = 0

    def get_bytes(self) -> bytes:
        """Get all bytes"""
        return bytes(self.vch)

    def serialize(self, obj):
        """Serialize object to stream"""
        serialize_to_stream(self, obj, self.n_type, self.n_version)

    def unserialize(self, obj):
        """Unserialize object from stream"""
        unserialize_from_stream(self, obj, self.n_type, self.n_version)


def serialize_to_stream(stream: DataStream, obj: Any, n_type: int = 0, n_version: int = VERSION):
    """Serialize object to stream"""
    if isinstance(obj, (int,)):
        if obj >= 0:
            stream.write(struct.pack("<Q", obj))
        else:
            stream.write(struct.pack("<q", obj))
    elif isinstance(obj, (str,)):
        data = obj.encode("utf-8")
        write_compact_size(stream.vch, len(data))
        stream.write(data)
    elif isinstance(obj, (bytes, bytearray)):
        write_compact_size(stream.vch, len(obj))
        stream.write(obj)
    elif isinstance(obj, (list, tuple)):
        write_compact_size(stream.vch, len(obj))
        for item in obj:
            serialize_to_stream(stream, item, n_type, n_version)
    elif isinstance(obj, dict):
        write_compact_size(stream.vch, len(obj))
        for key, value in obj.items():
            serialize_to_stream(stream, key, n_type, n_version)
            serialize_to_stream(stream, value, n_type, n_version)
    elif hasattr(obj, "serialize"):
        obj.serialize(stream, n_type, n_version)
    else:
        raise TypeError(f"Cannot serialize type {type(obj)}")


def unserialize_from_stream(
    stream: DataStream, obj: Any, n_type: int = 0, n_version: int = VERSION
):
    """Unserialize object from stream"""
    if isinstance(obj, int):
        data = stream.read(8)
        return struct.unpack("<q", data)[0]
    elif isinstance(obj, str):
        size, _ = read_compact_size(stream.vch, stream.n_read_pos)
        stream.n_read_pos += get_size_of_compact_size(size)
        data = stream.read(size)
        return data.decode("utf-8")
    elif isinstance(obj, (bytes, bytearray)):
        size, _ = read_compact_size(stream.vch, stream.n_read_pos)
        stream.n_read_pos += get_size_of_compact_size(size)
        return stream.read(size)
    elif hasattr(obj, "unserialize"):
        obj.unserialize(stream, n_type, n_version)
        return obj
    else:
        raise TypeError(f"Cannot unserialize type {type(obj)}")


def get_serialize_size(obj: Any, n_type: int = 0, n_version: int = VERSION) -> int:
    """Get serialized size of object"""
    if isinstance(obj, (int,)):
        return 8
    elif isinstance(obj, (str,)):
        data = obj.encode("utf-8")
        return get_size_of_compact_size(len(data)) + len(data)
    elif isinstance(obj, (bytes, bytearray)):
        return get_size_of_compact_size(len(obj)) + len(obj)
    elif isinstance(obj, (list, tuple)):
        size = get_size_of_compact_size(len(obj))
        for item in obj:
            size += get_serialize_size(item, n_type, n_version)
        return size
    elif isinstance(obj, dict):
        size = get_size_of_compact_size(len(obj))
        for key, value in obj.items():
            size += get_serialize_size(key, n_type, n_version)
            size += get_serialize_size(value, n_type, n_version)
        return size
    elif hasattr(obj, "get_serialize_size"):
        return obj.get_serialize_size(n_type, n_version)
    else:
        raise TypeError(f"Cannot get size for type {type(obj)}")
