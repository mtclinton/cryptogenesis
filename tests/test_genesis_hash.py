"""
Phase 0 invariant pin: the genesis block must hash to the mainnet value.

This guards consensus correctness across the whole refactor. It pins BOTH the
exported constant and the live construction path (serialization + double
SHA-256 + merkle root), so any change that breaks genesis is caught immediately.
"""

from .context import cryptogenesis

MAINNET_GENESIS_HASH = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"


def test_genesis_hash_constant():
    """The exported HASH_GENESIS_BLOCK constant matches mainnet."""
    assert cryptogenesis.HASH_GENESIS_BLOCK.get_hex() == MAINNET_GENESIS_HASH


def test_genesis_construction_hashes_to_invariant():
    """Building the genesis block from scratch reproduces the mainnet hash.

    This pins the real correctness path (coinbase assembly, CompactSize
    serialization, merkle root, double-SHA256 header hash), not just a constant.
    """
    from cryptogenesis.genesis import create_genesis_block

    genesis = create_genesis_block()
    assert genesis.get_hash().get_hex() == MAINNET_GENESIS_HASH
