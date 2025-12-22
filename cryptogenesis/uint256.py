"""
Copyright (c) 2009 Satoshi Nakamoto
Distributed under the MIT/X11 software license

256-bit unsigned integer implementation
"""

import struct


class uint256:
    """256-bit unsigned integer"""

    WIDTH = 8  # 8 * 32 bits = 256 bits

    def __init__(self, value=0):
        if isinstance(value, str):
            self.pn = [0] * self.WIDTH
            self.set_hex(value)
        elif isinstance(value, int):
            self.pn = [0] * self.WIDTH
            self.pn[0] = value & 0xFFFFFFFF
            self.pn[1] = (value >> 32) & 0xFFFFFFFF
        elif isinstance(value, bytes):
            if len(value) == 32:
                self.pn = list(struct.unpack("<8I", value))
            else:
                self.pn = [0] * self.WIDTH
        elif isinstance(value, uint256):
            self.pn = value.pn[:]
        else:
            self.pn = [0] * self.WIDTH

    def __eq__(self, other):
        if isinstance(other, int):
            return self.pn[0] == other and all(x == 0 for x in self.pn[1:])
        if isinstance(other, uint256):
            return self.pn == other.pn
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __lt__(self, other):
        if isinstance(other, uint256):
            for i in range(self.WIDTH - 1, -1, -1):
                if self.pn[i] < other.pn[i]:
                    return True
                elif self.pn[i] > other.pn[i]:
                    return False
            return False
        return False

    def __le__(self, other):
        return self.__lt__(other) or self.__eq__(other)

    def __gt__(self, other):
        if isinstance(other, uint256):
            for i in range(self.WIDTH - 1, -1, -1):
                if self.pn[i] > other.pn[i]:
                    return True
                elif self.pn[i] < other.pn[i]:
                    return False
            return False
        return False

    def __ge__(self, other):
        return self.__gt__(other) or self.__eq__(other)

    def __and__(self, other):
        result = uint256()
        if isinstance(other, uint256):
            for i in range(self.WIDTH):
                result.pn[i] = self.pn[i] & other.pn[i]
        return result

    def __or__(self, other):
        result = uint256()
        if isinstance(other, uint256):
            for i in range(self.WIDTH):
                result.pn[i] = self.pn[i] | other.pn[i]
        return result

    def __xor__(self, other):
        result = uint256()
        if isinstance(other, uint256):
            for i in range(self.WIDTH):
                result.pn[i] = self.pn[i] ^ other.pn[i]
        return result

    def __lshift__(self, shift):
        result = uint256()
        result.pn = self.pn[:]
        k = shift // 32
        shift = shift % 32
        for i in range(self.WIDTH):
            if i + k + 1 < self.WIDTH and shift != 0:
                result.pn[i + k + 1] |= self.pn[i] >> (32 - shift)
            if i + k < self.WIDTH:
                result.pn[i + k] |= self.pn[i] << shift
        return result

    def __rshift__(self, shift):
        result = uint256()
        k = shift // 32
        shift = shift % 32
        for i in range(self.WIDTH):
            if i - k - 1 >= 0 and shift != 0:
                result.pn[i - k - 1] |= self.pn[i] << (32 - shift)
            if i - k >= 0:
                result.pn[i - k] |= self.pn[i] >> shift
        return result

    def __add__(self, other):
        result = uint256()
        if isinstance(other, uint256):
            carry = 0
            for i in range(self.WIDTH):
                n = carry + self.pn[i] + other.pn[i]
                result.pn[i] = n & 0xFFFFFFFF
                carry = n >> 32
        return result

    def __sub__(self, other):
        return self.__add__(~other) + uint256(1)

    def __invert__(self):
        result = uint256()
        for i in range(self.WIDTH):
            result.pn[i] = ~self.pn[i] & 0xFFFFFFFF
        return result

    def set_hex(self, hex_str):
        """Set value from hex string"""
        hex_str = hex_str.strip()
        if hex_str.startswith("0x") or hex_str.startswith("0X"):
            hex_str = hex_str[2:]

        # Pad to 64 hex chars (32 bytes)
        hex_str = hex_str.zfill(64)

        # Convert hex string to bytes (little-endian)
        try:
            bytes_val = bytes.fromhex(hex_str)
            # Reverse for little-endian
            bytes_val = bytes_val[::-1]
            self.pn = list(struct.unpack("<8I", bytes_val))
        except Exception:
            self.pn = [0] * self.WIDTH

    def get_hex(self):
        """Get hex string representation"""
        bytes_val = struct.pack("<8I", *self.pn)
        # Reverse for display (big-endian)
        bytes_val = bytes_val[::-1]
        return bytes_val.hex()

    def to_string(self):
        """String representation"""
        return self.get_hex()

    def __str__(self):
        return self.to_string()

    def __repr__(self):
        return f"uint256('0x{self.get_hex()}')"

    def to_bytes(self):
        """Convert to 32-byte little-endian bytes"""
        return struct.pack("<8I", *self.pn)

    def begin(self):
        """Iterator begin"""
        return 0

    def end(self):
        """Iterator end"""
        return 32

    def __hash__(self):
        return hash(tuple(self.pn))


class uint160:
    """160-bit unsigned integer (for addresses)"""

    WIDTH = 5  # 5 * 32 bits = 160 bits

    def __init__(self, value=0):
        if isinstance(value, str):
            self.pn = [0] * self.WIDTH
            self.set_hex(value)
        elif isinstance(value, int):
            self.pn = [0] * self.WIDTH
            self.pn[0] = value & 0xFFFFFFFF
            self.pn[1] = (value >> 32) & 0xFFFFFFFF
        elif isinstance(value, bytes):
            if len(value) == 20:
                self.pn = list(struct.unpack("<5I", value))
            else:
                self.pn = [0] * self.WIDTH
        elif isinstance(value, uint160):
            self.pn = value.pn[:]
        else:
            self.pn = [0] * self.WIDTH

    def set_hex(self, hex_str):
        """Set value from hex string"""
        hex_str = hex_str.strip()
        if hex_str.startswith("0x") or hex_str.startswith("0X"):
            hex_str = hex_str[2:]

        hex_str = hex_str.zfill(40)
        try:
            bytes_val = bytes.fromhex(hex_str)
            bytes_val = bytes_val[::-1]
            self.pn = list(struct.unpack("<5I", bytes_val))
        except Exception:
            self.pn = [0] * self.WIDTH

    def get_hex(self):
        """Get hex string representation"""
        bytes_val = struct.pack("<5I", *self.pn)
        bytes_val = bytes_val[::-1]
        return bytes_val.hex()

    def to_bytes(self):
        """Convert to 20-byte little-endian bytes"""
        return struct.pack("<5I", *self.pn)

    def __eq__(self, other):
        if isinstance(other, uint160):
            return self.pn == other.pn
        return False

    def __hash__(self):
        return hash(tuple(self.pn))

    def __str__(self):
        return self.get_hex()

    def __repr__(self):
        return f"uint160('0x{self.get_hex()}')"
