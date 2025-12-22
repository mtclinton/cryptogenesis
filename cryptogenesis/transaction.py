"""
Copyright (c) 2009 Satoshi Nakamoto
Distributed under the MIT/X11 software license

Transaction and script system
"""

import struct
from typing import List

from cryptogenesis.crypto import double_sha256, hash_to_uint256
from cryptogenesis.serialize import DataStream
from cryptogenesis.uint256 import uint256

# Constants
COIN = 100000000
CENT = 1000000
COINBASE_MATURITY = 100
MAX_SIZE = 0x02000000

# Script opcodes
OP_0 = 0
OP_FALSE = OP_0
OP_PUSHDATA1 = 76
OP_PUSHDATA2 = 77
OP_PUSHDATA4 = 78
OP_1NEGATE = 79
OP_RESERVED = 80
OP_1 = 81
OP_TRUE = OP_1
OP_2 = 82
OP_3 = 83
OP_4 = 84
OP_5 = 85
OP_6 = 86
OP_7 = 87
OP_8 = 88
OP_9 = 89
OP_10 = 90
OP_11 = 91
OP_12 = 92
OP_13 = 93
OP_14 = 94
OP_15 = 95
OP_16 = 96
OP_NOP = 97
OP_VER = 98
OP_IF = 99
OP_NOTIF = 100
OP_VERIF = 101
OP_VERNOTIF = 102
OP_ELSE = 103
OP_ENDIF = 104
OP_VERIFY = 105
OP_RETURN = 106
OP_TOALTSTACK = 107
OP_FROMALTSTACK = 108
OP_2DROP = 109
OP_2DUP = 110
OP_3DUP = 111
OP_2OVER = 112
OP_2ROT = 113
OP_2SWAP = 114
OP_IFDUP = 115
OP_DEPTH = 116
OP_DROP = 117
OP_DUP = 118
OP_NIP = 119
OP_OVER = 120
OP_PICK = 121
OP_ROLL = 122
OP_ROT = 123
OP_SWAP = 124
OP_TUCK = 125
OP_CAT = 126
OP_SUBSTR = 127
OP_LEFT = 128
OP_RIGHT = 129
OP_SIZE = 130
OP_INVERT = 131
OP_AND = 132
OP_OR = 133
OP_XOR = 134
OP_EQUAL = 135
OP_EQUALVERIFY = 136
OP_RESERVED1 = 137
OP_RESERVED2 = 138
OP_1ADD = 139
OP_1SUB = 140
OP_2MUL = 141
OP_2DIV = 142
OP_NEGATE = 143
OP_ABS = 144
OP_NOT = 145
OP_0NOTEQUAL = 146
OP_ADD = 147
OP_SUB = 148
OP_MUL = 149
OP_DIV = 150
OP_MOD = 151
OP_LSHIFT = 152
OP_RSHIFT = 153
OP_BOOLAND = 154
OP_BOOLOR = 155
OP_NUMEQUAL = 156
OP_NUMEQUALVERIFY = 157
OP_NUMNOTEQUAL = 158
OP_LESSTHAN = 159
OP_GREATERTHAN = 160
OP_LESSTHANOREQUAL = 161
OP_GREATERTHANOREQUAL = 162
OP_MIN = 163
OP_MAX = 164
OP_WITHIN = 165
OP_RIPEMD160 = 166
OP_SHA1 = 167
OP_SHA256 = 168
OP_HASH160 = 169
OP_HASH256 = 170
OP_CODESEPARATOR = 171
OP_CHECKSIG = 172
OP_CHECKSIGVERIFY = 173
OP_CHECKMULTISIG = 174
OP_CHECKMULTISIGVERIFY = 175
OP_SINGLEBYTE_END = 0xF0
OP_DOUBLEBYTE_BEGIN = 0xF000
OP_PUBKEY = 0xF001
OP_PUBKEYHASH = 0xF002
OP_INVALIDOPCODE = 0xFFFF

# Signature hash types
SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
SIGHASH_ANYONECANPAY = 0x80


class OutPoint:
    """Reference to a transaction output"""

    def __init__(self, hash_tx: uint256 = None, n: int = 0):
        self.hash = hash_tx if hash_tx else uint256(0)
        self.n = n

    def set_null(self):
        """Set to null"""
        self.hash = uint256(0)
        self.n = -1

    def is_null(self) -> bool:
        """Check if null"""
        return self.hash == uint256(0) and self.n == -1

    @property
    def is_null_prop(self) -> bool:
        """Property version of is_null()"""
        return self.is_null()

    def serialize(self, stream: "DataStream", n_type: int = 0, n_version: int = 101):
        """Serialize to stream"""
        stream.write(self.hash.to_bytes())
        # Handle -1 (null) as 0xFFFFFFFF (max unsigned int)
        n_value = self.n if self.n >= 0 else 0xFFFFFFFF
        stream.write(struct.pack("<I", n_value))

    def unserialize(self, stream: "DataStream", n_type: int = 0, n_version: int = 101):
        """Unserialize from stream"""
        self.hash = hash_to_uint256(stream.read(32))
        n_value = struct.unpack("<I", stream.read(4))[0]
        # Convert 0xFFFFFFFF back to -1 (null)
        self.n = -1 if n_value == 0xFFFFFFFF else n_value

    def __eq__(self, other):
        return isinstance(other, OutPoint) and self.hash == other.hash and self.n == other.n

    def __hash__(self):
        return hash((self.hash, self.n))

    def __str__(self):
        return f"OutPoint({self.hash.get_hex()[:12]}, {self.n})"

    def __repr__(self):
        return f"OutPoint(hash={self.hash.get_hex()[:12]}, n={self.n})"

    def get_serialize_size(self, n_type: int = 0, n_version: int = 101) -> int:
        """Get serialized size"""
        return 32 + 4  # hash + n


class Script:
    """Bitcoin script"""

    def __init__(self, data: bytes = None):
        self.data = bytearray(data) if data else bytearray()

    def __add__(self, other):
        """Concatenate scripts"""
        result = Script()
        if isinstance(other, Script):
            result.data = self.data + other.data
        elif isinstance(other, (bytes, bytearray)):
            result.data = self.data + bytearray(other)
        return result

    def __iadd__(self, other):
        """In-place concatenation"""
        if isinstance(other, Script):
            self.data.extend(other.data)
        elif isinstance(other, (bytes, bytearray)):
            self.data.extend(other)
        return self

    def push_int(self, n: int, force_bignum: bool = False):
        """Push integer to script (using CBigNum encoding)

        Args:
            n: Integer to push
            force_bignum: If True, always use bignum encoding (like CBigNum)
        """
        if not force_bignum and (n == -1 or (1 <= n <= 16)):
            self.data.append(OP_1 + n - 1)
        else:
            # Push as variable-length integer (little-endian, like CBigNum.getvch())
            if n == 0:
                self.data.append(OP_0)
            else:
                # Encode as little-endian bytes (like CBigNum.getvch())
                # Handle negative numbers
                if n < 0:
                    abs_n = -n
                    neg = True
                else:
                    abs_n = n
                    neg = False

                # Convert to little-endian bytes, removing leading zeros
                bytes_data = bytearray()
                temp = abs_n
                while temp > 0:
                    bytes_data.append(temp & 0xFF)
                    temp >>= 8

                # Handle sign bit for negative numbers
                if neg:
                    # Set sign bit on last byte
                    if bytes_data and (bytes_data[-1] & 0x80) == 0:
                        bytes_data[-1] |= 0x80
                    else:
                        # Need to add a zero byte if MSB is already set
                        bytes_data.append(0x80)

                # Push data with length prefix
                if len(bytes_data) < OP_PUSHDATA1:
                    self.data.append(len(bytes_data))
                    self.data.extend(bytes_data)
                elif len(bytes_data) <= 0xFF:
                    self.data.append(OP_PUSHDATA1)
                    self.data.append(len(bytes_data))
                    self.data.extend(bytes_data)
                else:
                    self.data.append(OP_PUSHDATA2)
                    self.data.extend(struct.pack("<H", len(bytes_data)))
                    self.data.extend(bytes_data)

    def push_data(self, data: bytes):
        """Push data to script"""
        if len(data) < OP_PUSHDATA1:
            self.data.append(len(data))
            self.data.extend(data)
        elif len(data) <= 0xFF:
            self.data.append(OP_PUSHDATA1)
            self.data.append(len(data))
            self.data.extend(data)
        else:
            self.data.append(OP_PUSHDATA2)
            self.data.extend(struct.pack("<H", len(data)))
            self.data.extend(data)

    def push_opcode(self, opcode: int):
        """Push opcode to script"""
        if opcode <= OP_SINGLEBYTE_END:
            self.data.append(opcode)
        else:
            # Multi-byte opcode
            self.data.append((opcode >> 8) & 0xFF)
            self.data.append(opcode & 0xFF)

    def serialize(self, stream: "DataStream", n_type: int = 0, n_version: int = 101):
        """Serialize to stream"""
        from cryptogenesis.serialize import write_compact_size

        write_compact_size(stream.vch, len(self.data))
        stream.write(bytes(self.data))

    def unserialize(self, stream: "DataStream", n_type: int = 0, n_version: int = 101):
        """Unserialize from stream"""
        from cryptogenesis.serialize import get_size_of_compact_size, read_compact_size

        size, _ = read_compact_size(stream.vch, stream.n_read_pos)
        stream.n_read_pos += get_size_of_compact_size(size)
        self.data = bytearray(stream.read(size))

    def __str__(self):
        return self.data.hex()

    def __len__(self):
        return len(self.data)

    def get_serialize_size(self, n_type: int = 0, n_version: int = 101) -> int:
        """Get serialized size"""
        from cryptogenesis.serialize import get_size_of_compact_size

        return get_size_of_compact_size(len(self.data)) + len(self.data)


class TxIn:
    """Transaction input"""

    def __init__(
        self, prevout: "OutPoint" = None, script_sig: "Script" = None, sequence: int = 0xFFFFFFFF
    ):
        self.prevout = prevout if prevout else OutPoint()
        self.script_sig = script_sig if script_sig else Script()
        self.sequence = sequence

    def serialize(self, stream: "DataStream", n_type: int = 0, n_version: int = 101):
        """Serialize to stream"""
        self.prevout.serialize(stream, n_type, n_version)
        self.script_sig.serialize(stream, n_type, n_version)
        stream.write(struct.pack("<I", self.sequence))

    def unserialize(self, stream: "DataStream", n_type: int = 0, n_version: int = 101):
        """Unserialize from stream"""
        self.prevout.unserialize(stream, n_type, n_version)
        self.script_sig.unserialize(stream, n_type, n_version)
        self.sequence = struct.unpack("<I", stream.read(4))[0]

    def is_final(self) -> bool:
        """Check if input is final"""
        return self.sequence == 0xFFFFFFFF

    def get_serialize_size(self, n_type: int = 0, n_version: int = 101) -> int:
        """Get serialized size"""
        from cryptogenesis.serialize import get_serialize_size

        size = get_serialize_size(self.prevout, n_type, n_version)
        size += get_serialize_size(self.script_sig, n_type, n_version)
        size += 4  # sequence
        return size


class TxOut:
    """Transaction output"""

    def __init__(self, value: int = 0, script_pubkey: "Script" = None):
        self.value = value
        self.script_pubkey = script_pubkey if script_pubkey else Script()

    def serialize(self, stream: "DataStream", n_type: int = 0, n_version: int = 101):
        """Serialize to stream"""
        stream.write(struct.pack("<Q", self.value))
        self.script_pubkey.serialize(stream, n_type, n_version)

    def unserialize(self, stream: "DataStream", n_type: int = 0, n_version: int = 101):
        """Unserialize from stream"""
        self.value = struct.unpack("<Q", stream.read(8))[0]
        self.script_pubkey = Script()
        self.script_pubkey.unserialize(stream, n_type, n_version)

    def set_null(self):
        """Set to null"""
        self.value = -1
        self.script_pubkey = Script()

    def is_null(self) -> bool:
        """Check if null"""
        return self.value == -1

    def get_serialize_size(self, n_type: int = 0, n_version: int = 101) -> int:
        """Get serialized size"""
        from cryptogenesis.serialize import get_serialize_size

        size = 8  # value
        size += get_serialize_size(self.script_pubkey, n_type, n_version)
        return size


class Transaction:
    """Bitcoin transaction"""

    def __init__(self, version: int = 1, lock_time: int = 0):
        self.version = version
        self.vin: List["TxIn"] = []
        self.vout: List["TxOut"] = []
        self.lock_time = lock_time

    @property
    def txid(self) -> uint256:
        """Transaction ID (hash) - property version"""
        return self.get_hash()

    def get_hash(self) -> uint256:
        """Get transaction hash"""
        from cryptogenesis.serialize import DataStream

        stream = DataStream()
        self.serialize(stream)
        return hash_to_uint256(double_sha256(stream.get_bytes()))

    def serialize(self, stream: "DataStream", n_type: int = 0, n_version: int = 101):
        """Serialize to stream"""
        stream.write(struct.pack("<i", self.version))
        from cryptogenesis.serialize import write_compact_size

        write_compact_size(stream.vch, len(self.vin))
        for txin in self.vin:
            txin.serialize(stream, n_type, n_version)
        write_compact_size(stream.vch, len(self.vout))
        for txout in self.vout:
            txout.serialize(stream, n_type, n_version)
        stream.write(struct.pack("<I", self.lock_time))

    def unserialize(self, stream: "DataStream", n_type: int = 0, n_version: int = 101):
        """Unserialize from stream"""
        self.version = struct.unpack("<i", stream.read(4))[0]
        from cryptogenesis.serialize import get_size_of_compact_size, read_compact_size

        vin_size, _ = read_compact_size(stream.vch, stream.n_read_pos)
        stream.n_read_pos += get_size_of_compact_size(vin_size)
        self.vin = []
        for _ in range(vin_size):
            txin = TxIn()
            txin.unserialize(stream, n_type, n_version)
            self.vin.append(txin)
        vout_size, _ = read_compact_size(stream.vch, stream.n_read_pos)
        stream.n_read_pos += get_size_of_compact_size(vout_size)
        self.vout = []
        for _ in range(vout_size):
            txout = TxOut()
            txout.unserialize(stream, n_type, n_version)
            self.vout.append(txout)
        self.lock_time = struct.unpack("<I", stream.read(4))[0]

    def get_serialize_size(self, n_type: int = 0, n_version: int = 101) -> int:
        """Get serialized size"""
        from cryptogenesis.serialize import get_size_of_compact_size

        size = 4  # version
        size += get_size_of_compact_size(len(self.vin))
        for txin in self.vin:
            size += txin.get_serialize_size(n_type, n_version)
        size += get_size_of_compact_size(len(self.vout))
        for txout in self.vout:
            size += txout.get_serialize_size(n_type, n_version)
        size += 4  # lock_time
        return size

    def is_coinbase(self) -> bool:
        """Check if coinbase transaction"""
        return len(self.vin) == 1 and self.vin[0].prevout.is_null()

    def check_transaction(self) -> bool:
        """Basic transaction checks"""
        if len(self.vin) == 0 or len(self.vout) == 0:
            return False

        # Check for negative values
        for txout in self.vout:
            if txout.value < 0:
                return False

        if self.is_coinbase():
            if len(self.vin[0].script_sig.data) < 2 or len(self.vin[0].script_sig.data) > 100:
                return False
        else:
            for txin in self.vin:
                if txin.prevout.is_null():
                    return False

        return True

    @property
    def value_out(self) -> int:
        """Get total value of outputs - property version"""
        return self.get_value_out()

    def get_value_out(self) -> int:
        """Get total value of outputs"""
        total = 0
        for txout in self.vout:
            if txout.value < 0:
                raise ValueError("Negative output value")
            total += txout.value
        return total

    def is_final(self, best_height: int = 0) -> bool:
        """Check if transaction is final"""
        if self.lock_time == 0:
            return True
        if self.lock_time < best_height:
            return True
        for txin in self.vin:
            if not txin.is_final():
                return False
        return True

    def __str__(self):
        hash_str = self.get_hash().get_hex()[:12]
        return f"Transaction(hash={hash_str}, " f"vin={len(self.vin)}, vout={len(self.vout)})"

    def __repr__(self):
        return (
            f"Transaction(version={self.version}, "
            f"vin={len(self.vin)}, vout={len(self.vout)}, "
            f"lock_time={self.lock_time})"
        )
