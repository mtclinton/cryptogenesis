"""
Phase 9 pins: BlockchainState is the single source of truth.

BlockchainState is a thin facade over the one BlockChain engine, so the service,
the state, and get_chain() always agree -- there is no second store to drift.
add_block goes through a single path and rejects duplicates.
"""

from .context import cryptogenesis  # noqa: F401

from cryptogenesis.chain import BlockChain, get_chain
from cryptogenesis.events import EventBus
from cryptogenesis.genesis import create_genesis_block
from cryptogenesis.services import get_services
from cryptogenesis.services.blockchain_service import BlockchainService
from cryptogenesis.state.blockchain_state import BlockchainState


def _isolated_service():
    # Isolated BlockChain so the test never touches the global singleton.
    chain = BlockChain()
    state = BlockchainState(chain=chain)
    return BlockchainService(blockchain_state=state, event_bus=EventBus()), chain


def test_state_facades_a_single_chain():
    chain = BlockChain()
    state = BlockchainState(chain=chain)
    assert state.chain is chain


def test_add_genesis_is_single_source_of_truth():
    service, chain = _isolated_service()
    assert service.get_best_height() == -1

    result = service.add_block(create_genesis_block())
    assert result  # ServiceResult truthy on success

    # service, state, and the underlying chain all agree -- one store.
    assert service.get_best_height() == 0
    assert chain.best_height == 0
    assert service.get_best_hash().get_hex() == chain.get_best_hash().get_hex()
    assert service.get_best_index() is chain.get_best_index()


def test_duplicate_block_is_rejected():
    service, chain = _isolated_service()
    assert service.add_block(create_genesis_block())
    again = service.add_block(create_genesis_block())
    assert not again  # already in the index
    assert chain.best_height == 0  # unchanged


def test_get_services_state_facades_global_chain():
    services = get_services(EventBus())
    assert services.blockchain_service.blockchain_state.chain is get_chain()
