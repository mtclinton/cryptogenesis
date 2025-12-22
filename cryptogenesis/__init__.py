"""
Cryptogenesis - Bitcoin v0.1 Python 3 Implementation

A Python 3 re-implementation of the original Bitcoin protocol from 2009.
"""

__version__ = "0.1.0"

from cryptogenesis.block import HASH_GENESIS_BLOCK, Block, BlockIndex, get_next_work_required
from cryptogenesis.crypto import (
    Key,
    double_sha256,
    hash160,
    hash256,
    hash_to_uint256,
    ripemd160,
    serialize_hash,
    sha256,
)
from cryptogenesis.serialize import (
    DataStream,
    get_size_of_compact_size,
    read_compact_size,
    write_compact_size,
)
from cryptogenesis.transaction import (
    CENT,
    COIN,
    COINBASE_MATURITY,
    MAX_SIZE,
    OutPoint,
    Script,
    Transaction,
    TxIn,
    TxOut,
)
from cryptogenesis.uint256 import uint160, uint256

__all__ = [
    # Block
    "Block",
    "BlockIndex",
    "HASH_GENESIS_BLOCK",
    "get_next_work_required",
    # Crypto
    "Key",
    "double_sha256",
    "hash160",
    "hash256",
    "hash_to_uint256",
    "ripemd160",
    "sha256",
    # Serialize
    "DataStream",
    "get_size_of_compact_size",
    "read_compact_size",
    "write_compact_size",
    # Crypto (additional)
    "serialize_hash",
    # Transaction
    "COIN",
    "CENT",
    "COINBASE_MATURITY",
    "MAX_SIZE",
    "OutPoint",
    "Script",
    "Transaction",
    "TxIn",
    "TxOut",
    # Uint256
    "uint160",
    "uint256",
]
