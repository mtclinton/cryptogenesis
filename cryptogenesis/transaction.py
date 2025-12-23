"""
Copyright (c) 2009 Satoshi Nakamoto
Distributed under the MIT/X11 software license

Transaction and script system
"""

import struct
from typing import List, Optional

from cryptogenesis.crypto import double_sha256, hash_to_uint256
from cryptogenesis.serialize import DataStream
from cryptogenesis.uint256 import uint256
from cryptogenesis.util import error

# Constants
COIN = 100000000
CENT = 1000000
COINBASE_MATURITY = 100
MAX_SIZE = 0x02000000
# Dust threshold: outputs below this value are considered dust
# In Bitcoin v0.1, dust is typically defined as outputs that cost more
# in transaction fees to spend than they're worth
# Using CENT (1,000,000 satoshis) as a conservative dust threshold
DUST_THRESHOLD = CENT

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

    def get_op(self, pc: int) -> tuple[bool, int, int, Optional[bytes]]:
        """
        Get next opcode from script

        Args:
            pc: Current position in script

        Returns:
            (success, new_pc, opcode, data) tuple
            - success: True if opcode was read
            - new_pc: New position after reading
            - opcode: Opcode value
            - data: Push data (if opcode is push data), None otherwise
        """
        if pc >= len(self.data):
            return False, pc, OP_INVALIDOPCODE, None

        # Read instruction
        opcode = self.data[pc]
        pc += 1

        # Handle multi-byte opcodes
        if opcode >= OP_SINGLEBYTE_END:
            if pc >= len(self.data):
                return False, pc, OP_INVALIDOPCODE, None
            opcode = (opcode << 8) | self.data[pc]
            pc += 1

        # Handle push data opcodes
        data = None
        if opcode <= OP_PUSHDATA4:
            n_size = opcode
            if opcode == OP_PUSHDATA1:
                if pc >= len(self.data):
                    return False, pc, OP_INVALIDOPCODE, None
                n_size = self.data[pc]
                pc += 1
            elif opcode == OP_PUSHDATA2:
                if pc + 2 > len(self.data):
                    return False, pc, OP_INVALIDOPCODE, None
                n_size = struct.unpack("<H", bytes(self.data[pc : pc + 2]))[0]
                pc += 2
            elif opcode == OP_PUSHDATA4:
                if pc + 4 > len(self.data):
                    return False, pc, OP_INVALIDOPCODE, None
                n_size = struct.unpack("<I", bytes(self.data[pc : pc + 4]))[0]
                pc += 4

            if pc + n_size > len(self.data):
                return False, pc, OP_INVALIDOPCODE, None

            data = bytes(self.data[pc : pc + n_size])
            pc += n_size

        return True, pc, opcode, data

    def find_and_delete(self, script_to_find: "Script"):
        """Find and delete all occurrences of script_to_find"""
        # Simple byte-level search and delete
        script_bytes = bytes(script_to_find.data)
        i = 0
        while i < len(self.data):
            if i + len(script_bytes) <= len(self.data):
                if bytes(self.data[i : i + len(script_bytes)]) == script_bytes:
                    # Delete this occurrence
                    del self.data[i : i + len(script_bytes)]
                    continue
            i += 1


class TxIn:
    """Transaction input"""

    def __init__(
        self,
        prevout: "OutPoint" = None,
        script_sig: "Script" = None,
        sequence: int = 0xFFFFFFFF,
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

    def is_dust(self) -> bool:
        """
        Check if output is dust (value too small to be economically viable)
        Matches Bitcoin v0.1 dust validation logic
        Dust outputs are those where the value is less than the dust threshold
        """
        return self.value > 0 and self.value < DUST_THRESHOLD


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

    def get_min_fee(self, f_discount: bool = False) -> int:
        """
        Get minimum fee required for this transaction
        Matches Bitcoin v0.1 GetMinFee()

        Args:
            f_discount: If True, transactions under 10KB are free (for first 100 in block)

        Returns:
            Minimum fee in satoshis
        """
        from cryptogenesis.serialize import SER_NETWORK, get_serialize_size

        n_bytes = get_serialize_size(self, SER_NETWORK)
        if f_discount and n_bytes < 10000:
            return 0
        # Base rate is 0.01 per KB (1 CENT per KB)
        # Formula: (1 + nBytes / 1000) * CENT
        return (1 + n_bytes // 1000) * CENT

    def is_coinbase(self) -> bool:
        """Check if coinbase transaction"""
        return len(self.vin) == 1 and self.vin[0].prevout.is_null()

    def check_transaction(self) -> bool:
        """
        Basic transaction checks
        Matches Bitcoin v0.1 CheckTransaction()
        """
        if len(self.vin) == 0 or len(self.vout) == 0:
            return error("CheckTransaction() : vin or vout empty")

        # Check for negative values
        for txout in self.vout:
            if txout.value < 0:
                return error("CheckTransaction() : txout.value negative")

        # Check for dust outputs (outputs too small to be economically viable)
        # Dust validation matches Bitcoin v0.1 behavior
        for txout in self.vout:
            if txout.is_dust():
                return error(
                    "CheckTransaction() : txout.value is dust (%d < %d)",
                    txout.value,
                    DUST_THRESHOLD,
                )

        if self.is_coinbase():
            if len(self.vin[0].script_sig.data) < 2 or len(self.vin[0].script_sig.data) > 100:
                return False
        else:
            for txin in self.vin:
                if txin.prevout.is_null():
                    return False

        # Check transaction size limit (MAX_SIZE = 32 MB)
        # While not explicitly in CheckTransaction(), it's enforced in AcceptTransaction
        # and prevents extremely large transactions
        from cryptogenesis.serialize import SER_DISK

        tx_size = self.get_serialize_size(SER_DISK)
        if tx_size > MAX_SIZE:
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


# ============================================================================
# Script Evaluation Functions
# ============================================================================


# BigNum helper functions (CBigNum equivalent)
def bignum_from_bytes(vch: bytes) -> int:
    """Convert bytes to integer (little-endian, like CBigNum)"""
    if not vch:
        return 0

    # Check for negative (sign bit on last byte)
    is_negative = False
    if vch[-1] & 0x80:
        is_negative = True
        # Clear sign bit
        vch_list = list(vch)
        vch_list[-1] &= 0x7F
        vch = bytes(vch_list)

    # Convert little-endian bytes to integer
    result = 0
    for i, b in enumerate(vch):
        result |= b << (i * 8)

    return -result if is_negative else result


def bignum_to_bytes(n: int) -> bytes:
    """Convert integer to bytes (little-endian, like CBigNum.getvch())"""
    if n == 0:
        return b"\x00"

    is_negative = n < 0
    abs_n = abs(n)

    # Convert to little-endian bytes
    bytes_list = []
    while abs_n > 0:
        bytes_list.append(abs_n & 0xFF)
        abs_n >>= 8

    # Set sign bit if negative
    if is_negative:
        if bytes_list[-1] & 0x80:
            bytes_list.append(0x80)
        else:
            bytes_list[-1] |= 0x80

    return bytes(bytes_list)


def cast_to_bool(vch: bytes) -> bool:
    """Cast value to bool (non-zero is true)"""
    if not vch:
        return False
    # Check if all bytes are zero (except possibly sign bit)
    for b in vch:
        if b != 0:
            return True
    return False


def make_same_size(vch1: bytearray, vch2: bytearray):
    """Make two bytearrays the same size by padding with zeros"""
    if len(vch1) < len(vch2):
        vch1.extend(bytes(len(vch2) - len(vch1)))
    if len(vch2) < len(vch1):
        vch2.extend(bytes(len(vch1) - len(vch2)))


def signature_hash(script_code: Script, tx_to: Transaction, n_in: int, n_hash_type: int) -> uint256:
    """
    Compute signature hash for transaction

    Args:
        script_code: Script code to sign
        tx_to: Transaction being signed
        n_in: Input index
        n_hash_type: Hash type (SIGHASH_ALL, SIGHASH_NONE, etc.)

    Returns:
        Hash to sign
    """
    from cryptogenesis.serialize import SER_GETHASH, DataStream

    if n_in >= len(tx_to.vin):
        error("SignatureHash() : nIn=%d out of range", n_in)
        return uint256(1)

    # Create a copy of the transaction
    tx_tmp = Transaction()
    tx_tmp.version = tx_to.version
    tx_tmp.lock_time = tx_to.lock_time

    # Remove OP_CODESEPARATOR from script
    script_code_clean = Script()
    for i in range(len(script_code.data)):
        if script_code.data[i] != OP_CODESEPARATOR:
            script_code_clean.data.append(script_code.data[i])

    # Blank out other inputs' signatures
    tx_tmp.vin = []
    for i in range(len(tx_to.vin)):
        txin = TxIn()
        txin.prevout = tx_to.vin[i].prevout
        txin.sequence = tx_to.vin[i].sequence
        if i == n_in:
            txin.script_sig = script_code_clean
        else:
            txin.script_sig = Script()
        tx_tmp.vin.append(txin)

    # Copy outputs
    tx_tmp.vout = []
    for txout in tx_to.vout:
        txout_copy = TxOut()
        txout_copy.value = txout.value
        txout_copy.script_pubkey = Script()
        txout_copy.script_pubkey.data = txout.script_pubkey.data.copy()
        tx_tmp.vout.append(txout_copy)

    # Handle hash types
    if (n_hash_type & 0x1F) == SIGHASH_NONE:
        # Wildcard payee
        tx_tmp.vout.clear()
        # Let others update at will
        for i in range(len(tx_tmp.vin)):
            if i != n_in:
                tx_tmp.vin[i].sequence = 0
    elif (n_hash_type & 0x1F) == SIGHASH_SINGLE:
        # Only lockin the txout payee at same index as txin
        n_out = n_in
        if n_out >= len(tx_tmp.vout):
            error("SignatureHash() : nOut=%d out of range", n_out)
            return uint256(1)
        # Keep only the output at n_out
        tx_tmp.vout = tx_tmp.vout[: n_out + 1]
        for i in range(n_out):
            tx_tmp.vout[i].value = -1
            tx_tmp.vout[i].script_pubkey = Script()
        # Let others update at will
        for i in range(len(tx_tmp.vin)):
            if i != n_in:
                tx_tmp.vin[i].sequence = 0

    # Blank out other inputs completely if SIGHASH_ANYONECANPAY
    if n_hash_type & SIGHASH_ANYONECANPAY:
        tx_tmp.vin = [tx_tmp.vin[n_in]]

    # Serialize and hash
    stream = DataStream(SER_GETHASH, 101)
    tx_tmp.serialize(stream, SER_GETHASH, 101)
    stream.write(struct.pack("<I", n_hash_type))
    return hash_to_uint256(double_sha256(stream.get_bytes()))


def eval_script(
    script: Script,
    tx_to: Transaction,
    n_in: int,
    n_hash_type: int = 0,
    pv_stack_ret=None,
) -> bool:
    """
    Evaluate Bitcoin script (complete implementation with all opcodes)

    Args:
        script: Script to evaluate
        tx_to: Transaction being evaluated
        n_in: Input index
        n_hash_type: Hash type for signatures
        pv_stack_ret: Optional list to return stack

    Returns:
        True if script evaluates to true
    """
    from cryptogenesis.crypto import double_sha256, hash160, ripemd160, sha256

    pc = 0
    pbegin_code_hash = 0
    vf_exec = []  # Stack of execution flags for IF/ELSE/ENDIF
    stack = []  # Main stack
    altstack = []  # Alt stack

    if pv_stack_ret is not None:
        pv_stack_ret.clear()

    while pc < len(script.data):
        # Check if we're in an executed block
        f_exec = not (False in vf_exec)

        # Read instruction
        success, new_pc, opcode, data = script.get_op(pc)
        if not success:
            return False
        pc = new_pc

        # Handle push data
        if f_exec and data is not None:
            stack.append(data)
            continue
        elif not f_exec and not (OP_IF <= opcode <= OP_ENDIF):
            continue

        # Push value opcodes
        if OP_1NEGATE <= opcode <= OP_16:
            if f_exec:
                # Use same formula as original: (int)opcode - (int)(OP_1 - 1)
                # For OP_1NEGATE (79): 79 - 80 = -1
                # For OP_1 (81): 81 - 80 = 1
                # For OP_16 (96): 96 - 80 = 16
                value = opcode - (OP_1 - 1)
                stack.append(bignum_to_bytes(value))

        # Control opcodes
        elif opcode == OP_NOP:
            pass
        elif opcode == OP_VER:
            if f_exec:
                stack.append(bignum_to_bytes(101))  # VERSION
        elif opcode in (OP_IF, OP_NOTIF, OP_VERIF, OP_VERNOTIF):
            if f_exec:
                if len(stack) < 1:
                    return False
                vch = stack[-1]
                if opcode in (OP_VERIF, OP_VERNOTIF):
                    version_val = bignum_from_bytes(vch)
                    f_value = 101 >= version_val  # VERSION
                else:
                    f_value = cast_to_bool(vch)
                if opcode in (OP_NOTIF, OP_VERNOTIF):
                    f_value = not f_value
                stack.pop()
            else:
                f_value = False
            vf_exec.append(f_value)
        elif opcode == OP_ELSE:
            if not vf_exec:
                return False
            vf_exec[-1] = not vf_exec[-1]
        elif opcode == OP_ENDIF:
            if not vf_exec:
                return False
            vf_exec.pop()
        elif opcode == OP_VERIFY:
            if f_exec:
                if len(stack) < 1:
                    return False
                f_value = cast_to_bool(stack[-1])
                if f_value:
                    stack.pop()
                else:
                    # Set pc to end to exit loop (equivalent to pc = pend in original)
                    pc = len(script.data)
        elif opcode == OP_RETURN:
            # Set pc to end to exit loop (equivalent to pc = pend in original)
            pc = len(script.data)

        # Stack ops
        elif opcode == OP_TOALTSTACK:
            if f_exec:
                if len(stack) < 1:
                    return False
                altstack.append(stack[-1])
                stack.pop()
        elif opcode == OP_FROMALTSTACK:
            if f_exec:
                if len(altstack) < 1:
                    return False
                stack.append(altstack[-1])
                altstack.pop()
        elif opcode == OP_2DROP:
            if f_exec:
                if len(stack) < 2:
                    return False
                stack.pop()
                stack.pop()
        elif opcode == OP_2DUP:
            if f_exec:
                if len(stack) < 2:
                    return False
                stack.append(stack[-2])
                stack.append(stack[-1])
        elif opcode == OP_3DUP:
            if f_exec:
                if len(stack) < 3:
                    return False
                stack.append(stack[-3])
                stack.append(stack[-2])
                stack.append(stack[-1])
        elif opcode == OP_2OVER:
            if f_exec:
                if len(stack) < 4:
                    return False
                stack.append(stack[-4])
                stack.append(stack[-3])
        elif opcode == OP_2ROT:
            if f_exec:
                if len(stack) < 6:
                    return False
                vch1 = stack[-6]
                vch2 = stack[-5]
                del stack[-6:-4]
                stack.append(vch1)
                stack.append(vch2)
        elif opcode == OP_2SWAP:
            if f_exec:
                if len(stack) < 4:
                    return False
                stack[-4], stack[-2] = stack[-2], stack[-4]
                stack[-3], stack[-1] = stack[-1], stack[-3]
        elif opcode == OP_IFDUP:
            if f_exec:
                if len(stack) < 1:
                    return False
                if cast_to_bool(stack[-1]):
                    stack.append(stack[-1])
        elif opcode == OP_DEPTH:
            if f_exec:
                stack.append(bignum_to_bytes(len(stack)))
        elif opcode == OP_DROP:
            if f_exec:
                if len(stack) < 1:
                    return False
                stack.pop()
        elif opcode == OP_DUP:
            if f_exec:
                if len(stack) < 1:
                    return False
                stack.append(stack[-1])
        elif opcode == OP_NIP:
            if f_exec:
                if len(stack) < 2:
                    return False
                del stack[-2]
        elif opcode == OP_OVER:
            if f_exec:
                if len(stack) < 2:
                    return False
                stack.append(stack[-2])
        elif opcode == OP_PICK:
            if f_exec:
                if len(stack) < 2:
                    return False
                n = bignum_from_bytes(stack[-1])
                stack.pop()
                if n < 0 or n >= len(stack):
                    return False
                stack.append(stack[-n - 1])
        elif opcode == OP_ROLL:
            if f_exec:
                if len(stack) < 2:
                    return False
                n = bignum_from_bytes(stack[-1])
                stack.pop()
                if n < 0 or n >= len(stack):
                    return False
                vch = stack[-n - 1]
                del stack[-n - 1]
                stack.append(vch)
        elif opcode == OP_ROT:
            if f_exec:
                if len(stack) < 3:
                    return False
                stack[-3], stack[-2] = stack[-2], stack[-3]
                stack[-2], stack[-1] = stack[-1], stack[-2]
        elif opcode == OP_SWAP:
            if f_exec:
                if len(stack) < 2:
                    return False
                stack[-2], stack[-1] = stack[-1], stack[-2]
        elif opcode == OP_TUCK:
            if f_exec:
                if len(stack) < 2:
                    return False
                stack.insert(-2, stack[-1])

        # Splice ops
        elif opcode == OP_CAT:
            if f_exec:
                if len(stack) < 2:
                    return False
                vch1 = bytearray(stack[-2])
                vch2 = stack[-1]
                vch1.extend(vch2)
                stack.pop()
                stack.pop()
                stack.append(bytes(vch1))
        elif opcode == OP_SUBSTR:
            if f_exec:
                if len(stack) < 3:
                    return False
                vch = bytearray(stack[-3])
                n_begin = bignum_from_bytes(stack[-2])
                n_size = bignum_from_bytes(stack[-1])
                n_end = n_begin + n_size
                if n_begin < 0 or n_end < n_begin:
                    return False
                if n_begin > len(vch):
                    n_begin = len(vch)
                if n_end > len(vch):
                    n_end = len(vch)
                del vch[n_end:]
                del vch[:n_begin]
                stack.pop()
                stack.pop()
                stack.pop()
                stack.append(bytes(vch))
        elif opcode == OP_LEFT:
            if f_exec:
                if len(stack) < 2:
                    return False
                vch = bytearray(stack[-2])
                n_size = bignum_from_bytes(stack[-1])
                if n_size < 0:
                    return False
                if n_size > len(vch):
                    n_size = len(vch)
                del vch[n_size:]
                stack.pop()
                stack.pop()
                stack.append(bytes(vch))
        elif opcode == OP_RIGHT:
            if f_exec:
                if len(stack) < 2:
                    return False
                vch = bytearray(stack[-2])
                n_size = bignum_from_bytes(stack[-1])
                if n_size < 0:
                    return False
                if n_size > len(vch):
                    n_size = len(vch)
                del vch[: len(vch) - n_size]
                stack.pop()
                stack.pop()
                stack.append(bytes(vch))
        elif opcode == OP_SIZE:
            if f_exec:
                if len(stack) < 1:
                    return False
                stack.append(bignum_to_bytes(len(stack[-1])))

        # Bitwise ops
        elif opcode == OP_INVERT:
            if f_exec:
                if len(stack) < 1:
                    return False
                vch = bytearray(stack[-1])
                for i in range(len(vch)):
                    vch[i] = ~vch[i] & 0xFF
                stack[-1] = bytes(vch)
        elif opcode in (OP_AND, OP_OR, OP_XOR):
            if f_exec:
                if len(stack) < 2:
                    return False
                vch1 = bytearray(stack[-2])
                vch2 = bytearray(stack[-1])
                make_same_size(vch1, vch2)
                if opcode == OP_AND:
                    for i in range(len(vch1)):
                        vch1[i] &= vch2[i]
                elif opcode == OP_OR:
                    for i in range(len(vch1)):
                        vch1[i] |= vch2[i]
                elif opcode == OP_XOR:
                    for i in range(len(vch1)):
                        vch1[i] ^= vch2[i]
                stack.pop()
                stack.pop()
                stack.append(bytes(vch1))
        elif opcode in (OP_EQUAL, OP_EQUALVERIFY):
            if f_exec:
                if len(stack) < 2:
                    return False
                f_equal = stack[-2] == stack[-1]
                stack.pop()
                stack.pop()
                stack.append(bytes([1]) if f_equal else bytes([0]))
                if opcode == OP_EQUALVERIFY:
                    if f_equal:
                        stack.pop()
                    else:
                        # Set pc to end to exit loop (equivalent to pc = pend in original)
                        pc = len(script.data)

        # Numeric ops (single operand)
        elif opcode in (
            OP_1ADD,
            OP_1SUB,
            OP_2MUL,
            OP_2DIV,
            OP_NEGATE,
            OP_ABS,
            OP_NOT,
            OP_0NOTEQUAL,
        ):
            if f_exec:
                if len(stack) < 1:
                    return False
                bn = bignum_from_bytes(stack[-1])
                if opcode == OP_1ADD:
                    bn += 1
                elif opcode == OP_1SUB:
                    bn -= 1
                elif opcode == OP_2MUL:
                    bn <<= 1
                elif opcode == OP_2DIV:
                    bn >>= 1
                elif opcode == OP_NEGATE:
                    bn = -bn
                elif opcode == OP_ABS:
                    bn = abs(bn)
                elif opcode == OP_NOT:
                    bn = 1 if (bn == 0) else 0
                elif opcode == OP_0NOTEQUAL:
                    bn = 1 if (bn != 0) else 0
                stack.pop()
                stack.append(bignum_to_bytes(bn))

        # Numeric ops (two operands)
        elif opcode in (
            OP_ADD,
            OP_SUB,
            OP_MUL,
            OP_DIV,
            OP_MOD,
            OP_LSHIFT,
            OP_RSHIFT,
            OP_BOOLAND,
            OP_BOOLOR,
            OP_NUMEQUAL,
            OP_NUMEQUALVERIFY,
            OP_NUMNOTEQUAL,
            OP_LESSTHAN,
            OP_GREATERTHAN,
            OP_LESSTHANOREQUAL,
            OP_GREATERTHANOREQUAL,
            OP_MIN,
            OP_MAX,
        ):
            if f_exec:
                if len(stack) < 2:
                    return False
                bn1 = bignum_from_bytes(stack[-2])
                bn2 = bignum_from_bytes(stack[-1])
                bn = 0

                if opcode == OP_ADD:
                    bn = bn1 + bn2
                elif opcode == OP_SUB:
                    bn = bn1 - bn2
                elif opcode == OP_MUL:
                    bn = bn1 * bn2
                elif opcode == OP_DIV:
                    if bn2 == 0:
                        return False
                    bn = bn1 // bn2
                elif opcode == OP_MOD:
                    if bn2 == 0:
                        return False
                    bn = bn1 % bn2
                elif opcode == OP_LSHIFT:
                    if bn2 < 0:
                        return False
                    bn = bn1 << int(bn2)
                elif opcode == OP_RSHIFT:
                    if bn2 < 0:
                        return False
                    bn = bn1 >> int(bn2)
                elif opcode == OP_BOOLAND:
                    bn = 1 if (bn1 != 0 and bn2 != 0) else 0
                elif opcode == OP_BOOLOR:
                    bn = 1 if (bn1 != 0 or bn2 != 0) else 0
                elif opcode == OP_NUMEQUAL:
                    bn = 1 if (bn1 == bn2) else 0
                elif opcode == OP_NUMEQUALVERIFY:
                    bn = 1 if (bn1 == bn2) else 0
                elif opcode == OP_NUMNOTEQUAL:
                    bn = 1 if (bn1 != bn2) else 0
                elif opcode == OP_LESSTHAN:
                    bn = 1 if (bn1 < bn2) else 0
                elif opcode == OP_GREATERTHAN:
                    bn = 1 if (bn1 > bn2) else 0
                elif opcode == OP_LESSTHANOREQUAL:
                    bn = 1 if (bn1 <= bn2) else 0
                elif opcode == OP_GREATERTHANOREQUAL:
                    bn = 1 if (bn1 >= bn2) else 0
                elif opcode == OP_MIN:
                    bn = bn1 if (bn1 < bn2) else bn2
                elif opcode == OP_MAX:
                    bn = bn1 if (bn1 > bn2) else bn2

                stack.pop()
                stack.pop()
                stack.append(bignum_to_bytes(bn))

                if opcode == OP_NUMEQUALVERIFY:
                    if bn != 0:
                        stack.pop()
                    else:
                        # Set pc to end to exit loop (equivalent to pc = pend in original)
                        pc = len(script.data)

        elif opcode == OP_WITHIN:
            if f_exec:
                if len(stack) < 3:
                    return False
                bn1 = bignum_from_bytes(stack[-3])
                bn2 = bignum_from_bytes(stack[-2])
                bn3 = bignum_from_bytes(stack[-1])
                f_value = bn2 <= bn1 < bn3
                stack.pop()
                stack.pop()
                stack.pop()
                stack.append(bytes([1]) if f_value else bytes([0]))

        # Crypto ops
        elif opcode in (OP_RIPEMD160, OP_SHA1, OP_SHA256, OP_HASH160, OP_HASH256):
            if f_exec:
                if len(stack) < 1:
                    return False
                vch = stack[-1]
                if opcode == OP_RIPEMD160:
                    vch_hash = ripemd160(vch)
                elif opcode == OP_SHA1:
                    import hashlib

                    vch_hash = hashlib.sha1(vch).digest()
                elif opcode == OP_SHA256:
                    vch_hash = sha256(vch)
                elif opcode == OP_HASH160:
                    vch_hash = hash160(vch)
                elif opcode == OP_HASH256:
                    vch_hash = double_sha256(vch)
                stack.pop()
                stack.append(vch_hash)

        elif opcode == OP_CODESEPARATOR:
            pbegin_code_hash = pc

        elif opcode in (OP_CHECKSIG, OP_CHECKSIGVERIFY):
            if f_exec:
                if len(stack) < 2:
                    return False
                vch_sig = stack[-2]
                vch_pubkey = stack[-1]

                # Subset of script starting at most recent codeseparator
                script_code = Script()
                script_code.data = script.data[pbegin_code_hash:]

                # Drop the signature from script code
                sig_script = Script(vch_sig)
                script_code.find_and_delete(sig_script)

                f_success = check_sig(vch_sig, vch_pubkey, script_code, tx_to, n_in, n_hash_type)
                stack.pop()
                stack.pop()
                stack.append(bytes([1]) if f_success else bytes([0]))
                if opcode == OP_CHECKSIGVERIFY:
                    if f_success:
                        stack.pop()
                    else:
                        # Set pc to end to exit loop (equivalent to pc = pend in original)
                        pc = len(script.data)

        elif opcode in (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY):
            if f_exec:
                # Stack order (from top): num_pubkeys, pubkeys..., num_sigs, sigs...
                i = 1
                if len(stack) < i:
                    return False

                n_keys_count = bignum_from_bytes(stack[-i])
                if n_keys_count < 0:
                    return False
                ikey = i + 1  # First pubkey at stack[-ikey]
                i += n_keys_count
                if len(stack) < i:
                    return False

                n_sigs_count = bignum_from_bytes(stack[-i])
                if n_sigs_count < 0 or n_sigs_count > n_keys_count:
                    return False
                isig = i + 1  # First signature at stack[-isig]
                i += n_sigs_count
                if len(stack) < i:
                    return False

                # Subset of script starting at most recent codeseparator
                script_code = Script()
                script_code.data = script.data[pbegin_code_hash:]

                # Drop the signatures from script code (in reverse order to match original)
                for j in range(n_sigs_count):
                    vch_sig = stack[-isig - j]
                    sig_script = Script(vch_sig)
                    script_code.find_and_delete(sig_script)

                f_success = True
                while f_success and n_sigs_count > 0:
                    vch_sig = stack[-isig]
                    vch_pubkey = stack[-ikey]

                    # Check signature
                    if check_sig(vch_sig, vch_pubkey, script_code, tx_to, n_in, n_hash_type):
                        isig += 1
                        n_sigs_count -= 1
                    ikey += 1
                    n_keys_count -= 1

                    # If there are more signatures left than keys left, too many failed
                    if n_sigs_count > n_keys_count:
                        f_success = False

                # Pop all items (i total items)
                for _ in range(i):
                    stack.pop()

                stack.append(bytes([1]) if f_success else bytes([0]))

                if opcode == OP_CHECKMULTISIGVERIFY:
                    if f_success:
                        stack.pop()
                    else:
                        # Set pc to end to exit loop (equivalent to pc = pend in original)
                        pc = len(script.data)

        else:
            # Unknown opcode
            return False

    if pv_stack_ret is not None:
        pv_stack_ret.extend(stack)

    # Script is valid if stack is non-empty and top element is true
    if not stack:
        return False
    return cast_to_bool(stack[-1])


def verify_signature(
    tx_from: Transaction, tx_to: Transaction, n_in: int, n_hash_type: int = 0
) -> bool:
    """
    Verify signature for transaction input

    Args:
        tx_from: Previous transaction (contains the output being spent)
        tx_to: Current transaction (contains the input being verified)
        n_in: Input index in tx_to
        n_hash_type: Hash type

    Returns:
        True if signature is valid
    """
    if n_in >= len(tx_to.vin):
        return False

    txin = tx_to.vin[n_in]
    if txin.prevout.n >= len(tx_from.vout):
        return False

    txout = tx_from.vout[txin.prevout.n]

    if txin.prevout.hash != tx_from.get_hash():
        return False

    # Combine scriptSig and scriptPubKey with OP_CODESEPARATOR
    combined_script = Script()
    combined_script.data = txin.script_sig.data.copy()
    combined_script.data.append(OP_CODESEPARATOR)
    combined_script.data.extend(txout.script_pubkey.data)

    return eval_script(combined_script, tx_to, n_in, n_hash_type)


def check_sig(
    vch_sig: bytes,
    vch_pubkey: bytes,
    script_code: Script,
    tx_to: Transaction,
    n_in: int,
    n_hash_type: int = 0,
) -> bool:
    """
    Check signature

    Args:
        vch_sig: Signature bytes
        vch_pubkey: Public key bytes
        script_code: Script code
        tx_to: Transaction being verified
        n_in: Input index
        n_hash_type: Hash type (0 means extract from signature)

    Returns:
        True if signature is valid
    """
    from cryptogenesis.crypto import Key

    if not vch_sig:
        return False

    # Extract hash type from signature
    if n_hash_type == 0:
        n_hash_type = vch_sig[-1]
    elif n_hash_type != vch_sig[-1]:
        return False

    # Remove hash type byte
    vch_sig_clean = vch_sig[:-1]

    # Create key from public key
    try:
        key = Key()
        key.set_pubkey(vch_pubkey)
    except Exception:
        return False

    # Compute signature hash
    hash_sig = signature_hash(script_code, tx_to, n_in, n_hash_type)

    # Verify signature
    try:
        return key.verify(hash_sig, vch_sig_clean)
    except Exception:
        return False


# Add connect_inputs as a method to Transaction class
# This is defined outside the class but will be attached as a method
def _connect_inputs_impl(
    self,
    txdb,
    map_test_pool=None,
    pos_this_tx=None,
    height: int = 0,
    fees: int = 0,
    is_block: bool = False,
    is_miner: bool = False,
    min_fee: int = 0,
) -> tuple[bool, int]:
    """
    Connect transaction inputs - validate inputs and mark outputs as spent

    Args:
        txdb: Transaction database
        map_test_pool: Test pool for miner (optional)
        pos_this_tx: Position of this transaction
        height: Block height
        fees: Accumulated fees (output parameter)
        is_block: True if connecting in a block
        is_miner: True if called by miner
        min_fee: Minimum fee required

    Returns:
        (success, fees) tuple
    """
    from cryptogenesis.chain import get_chain
    from cryptogenesis.mempool import get_mempool
    from cryptogenesis.utxo import DiskTxPos, TxIndex

    if map_test_pool is None:
        map_test_pool = {}
    if pos_this_tx is None:
        pos_this_tx = DiskTxPos(1, 1, 1)

    if self.is_coinbase():
        # Coinbase has no inputs to connect
        if is_block:
            # Add transaction to disk index
            if not txdb.add_tx_index(self, pos_this_tx, height):
                return (
                    error(
                        "ConnectInputs() : AddTxIndex failed for %s",
                        self.get_hash().get_hex()[:6],
                    ),
                    fees,
                )
        elif is_miner:
            # Add transaction to test pool
            map_test_pool[self.get_hash()] = TxIndex(DiskTxPos(1, 1, 1), len(self.vout))
        return True, fees

    # Validate inputs
    value_in = 0
    chain = get_chain()
    mempool = get_mempool()

    for i, txin in enumerate(self.vin):
        prevout = txin.prevout

        # Read txindex
        txindex = None
        found = False

        if is_miner and prevout.hash in map_test_pool:
            # Get txindex from current proposed changes
            txindex = map_test_pool[prevout.hash]
            found = True
        else:
            # Read txindex from txdb
            txindex = txdb.read_tx_index(prevout.hash)
            found = txindex is not None

        if not found and (is_block or is_miner):
            if is_miner:
                return False, fees
            print(
                f"ConnectInputs() : {self.get_hash().get_hex()[:6]} "
                f"prev tx {prevout.hash.get_hex()[:6]} index entry not found"
            )
            return False, fees

        # Read previous transaction
        tx_prev = None
        if not found or txindex.pos == DiskTxPos(1, 1, 1):
            # Get prev tx from mempool or database
            tx_prev = mempool.get_transaction(prevout.hash)
            if not tx_prev:
                tx_prev = txdb.read_disk_tx(prevout.hash)
            if not tx_prev:
                print(
                    f"ConnectInputs() : {self.get_hash().get_hex()[:6]} "
                    f"mapTransactions prev not found {prevout.hash.get_hex()[:6]}"
                )
                return False, fees
            if not found:
                # Create new txindex for mempool transaction
                txindex = TxIndex(DiskTxPos(1, 1, 1), len(tx_prev.vout))
        else:
            # Get prev tx from disk
            tx_prev = txdb.read_disk_tx(prevout.hash)
            if not tx_prev:
                print(
                    f"ConnectInputs() : {self.get_hash().get_hex()[:6]} "
                    f"ReadFromDisk prev tx {prevout.hash.get_hex()[:6]} failed"
                )
                return False, fees

        # Check output index
        if prevout.n >= len(tx_prev.vout) or prevout.n >= len(txindex.spent):
            print(
                f"ConnectInputs() : {self.get_hash().get_hex()[:6]} "
                f"prevout.n out of range {prevout.n} {len(tx_prev.vout)} {len(txindex.spent)}"
            )
            return False, fees

        # If prev is coinbase, check that it's matured
        if tx_prev.is_coinbase():
            from cryptogenesis.transaction import COINBASE_MATURITY

            best = chain.get_best_index()
            best_height = chain.get_best_height()

            if best and best_height >= 0:
                # Walk back from best block, checking blocks at depth < COINBASE_MATURITY-1
                # (i.e., depth 0 to COINBASE_MATURITY-2, since COINBASE_MATURITY is 100)
                pindex = best
                while pindex and (best_height - pindex.height) < (COINBASE_MATURITY - 1):
                    # Check if this block's position matches the coinbase transaction's position
                    if (
                        not txindex.pos.is_null()
                        and pindex.file_num == txindex.pos.file_num
                        and pindex.block_pos == txindex.pos.block_pos
                    ):
                        depth = best_height - pindex.height
                        return (
                            error(
                                "ConnectInputs() : tried to spend coinbase at depth %d",
                                depth,
                            ),
                            fees,
                        )
                    pindex = pindex.prev

        # Verify signature
        if not verify_signature(tx_prev, self, i, 0):
            error(
                "ConnectInputs() : %s VerifySignature failed",
                self.get_hash().get_hex()[:6],
            )
            return False, fees
            return False, fees

        # Check for conflicts
        if not txindex.spent[prevout.n].is_null():
            if is_miner:
                return False, fees
            print(
                f"ConnectInputs() : {self.get_hash().get_hex()[:6]} "
                f"prev tx already used at {txindex.spent[prevout.n]}"
            )
            return False, fees

        # Mark outpoints as spent
        txindex.spent[prevout.n] = pos_this_tx

        # Write back
        if is_block:
            txdb.update_tx_index(prevout.hash, txindex)
        elif is_miner:
            map_test_pool[prevout.hash] = txindex

        value_in += tx_prev.vout[prevout.n].value

    # Tally transaction fees
    tx_fee = value_in - self.get_value_out()
    if tx_fee < 0:
        return (
            error(
                "ConnectInputs() : %s nTxFee < 0",
                self.get_hash().get_hex()[:6],
            ),
            fees,
        )
    # Strict minimum fee enforcement (matches Bitcoin v0.1)
    if min_fee > 0 and tx_fee < min_fee:
        return (
            error(
                "ConnectInputs() : %s nTxFee < nMinFee (%d < %d)",
                self.get_hash().get_hex()[:6],
                tx_fee,
                min_fee,
            ),
            fees,
        )
    fees += tx_fee

    if is_block:
        # Add transaction to disk index
        if not txdb.add_tx_index(self, pos_this_tx, height):
            return (
                error(
                    "ConnectInputs() : AddTxIndex failed for %s",
                    self.get_hash().get_hex()[:6],
                ),
                fees,
            )
    elif is_miner:
        # Add transaction to test pool
        map_test_pool[self.get_hash()] = TxIndex(DiskTxPos(1, 1, 1), len(self.vout))

    return True, fees


# Attach connect_inputs as a method to Transaction class (monkey-patching)
Transaction.connect_inputs = _connect_inputs_impl  # type: ignore[attr-defined]


# Add disconnect_inputs as a method to Transaction class
def _disconnect_inputs_impl(self, txdb) -> bool:
    """
    Disconnect transaction inputs - unmark outputs as spent

    Args:
        txdb: Transaction database

    Returns:
        True if successful
    """
    if self.is_coinbase():
        # Coinbase has no inputs to disconnect
        # Remove transaction from index
        if not txdb.erase_tx_index(self):
            return error("DisconnectInputs() : EraseTxIndex failed")
        return True

    # Unmark outputs as spent
    for txin in self.vin:
        prevout = txin.prevout

        # Get prev txindex from database
        txindex = txdb.read_tx_index(prevout.hash)
        if not txindex:
            return error("DisconnectInputs() : ReadTxIndex failed")

        if prevout.n >= len(txindex.spent):
            return error("DisconnectInputs() : prevout.n out of range")

        # Mark outpoint as not spent
        txindex.spent[prevout.n].set_null()

        # Write back
        txdb.update_tx_index(prevout.hash, txindex)

    # Remove transaction from index
    if not txdb.erase_tx_index(self):
        return error("DisconnectInputs() : EraseTxIndex failed")

    return True


# Attach disconnect_inputs as a method to Transaction class (monkey-patching)
Transaction.disconnect_inputs = _disconnect_inputs_impl  # type: ignore[attr-defined]
