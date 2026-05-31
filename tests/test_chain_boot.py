"""
Phase 0 chain regression gate: booting genesis and the BlockIndex prev-walk
that the /api visualizer depends on.

Uses an ISOLATED BlockChain instance (not the get_chain() global) so it cannot
introduce cross-test order dependence. This captures the chain-boot contract
BEFORE the state-ownership surgery moves accept/connect into BlockchainService,
so a regression in that move is caught.
"""

from .context import cryptogenesis  # noqa: F401

from cryptogenesis.chain import BlockChain

MAINNET_GENESIS_HASH = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"


def _genesis():
    import sys

    sys.argv = ["pytest"]
    import run_node

    return run_node.create_genesis_block()


def test_fresh_chain_starts_empty():
    chain = BlockChain()
    assert chain.best_height == -1


def test_accept_genesis_sets_best_tip():
    chain = BlockChain()
    genesis = _genesis()
    assert chain.accept_block(genesis) is True
    assert chain.best_height == 0
    assert chain.get_best_hash().get_hex() == MAINNET_GENESIS_HASH


def test_block_index_supports_prev_walk_for_api():
    # /api/blockchain walks best_index + .prev + .height + get_block(); pin that
    # contract so the read source can later move to BlockchainState's linked index.
    chain = BlockChain()
    genesis = _genesis()
    chain.accept_block(genesis)

    best_index = chain.get_best_index()
    assert best_index is not None
    assert best_index.height == 0
    assert best_index.prev is None  # genesis has no parent
    assert chain.get_block(best_index.block_hash) is not None
