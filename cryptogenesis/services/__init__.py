"""
Service Layer

Orchestrates core logic with state management.
Provides high-level operations for blockchain, wallet, mining, and network.
"""

from typing import Optional

from cryptogenesis.events import EventBus
from cryptogenesis.services.blockchain_service import BlockchainService, BlockValidator
from cryptogenesis.services.mempool_service import MempoolService
from cryptogenesis.services.mining_service import MiningService
from cryptogenesis.services.network_service import NetworkService
from cryptogenesis.services.service_result import ServiceResult
from cryptogenesis.services.wallet_service import WalletService
from cryptogenesis.state.blockchain_state import BlockchainState
from cryptogenesis.state.mempool_state import MempoolState
from cryptogenesis.state.network_state import NetworkState
from cryptogenesis.state.wallet_state import WalletState


class Services:
    """
    Container for all services.
    
    Provides access to all service instances with proper dependency injection.
    """
    
    def __init__(
        self,
        blockchain_service: BlockchainService,
        wallet_service: WalletService,
        mining_service: MiningService,
        network_service: NetworkService,
        mempool_service: MempoolService,
    ):
        """
        Initialize services container.
        
        Args:
            blockchain_service: BlockchainService instance
            wallet_service: WalletService instance
            mining_service: MiningService instance
            network_service: NetworkService instance
            mempool_service: MempoolService instance
        """
        self.blockchain_service = blockchain_service
        self.wallet_service = wallet_service
        self.mining_service = mining_service
        self.network_service = network_service
        self.mempool_service = mempool_service


def get_services(event_bus: Optional[EventBus] = None) -> Services:
    """
    Create and initialize all services with proper dependencies.
    
    Uses dependency injection pattern to create:
    - All state instances (BlockchainState, WalletState, MempoolState, NetworkState)
    - All service instances with proper dependencies
    
    Args:
        event_bus: Optional EventBus instance (for Phase 3 event system)
        
    Returns:
        Services object containing all service instances
    """
    # Step 1: Create all state instances
    blockchain_state = BlockchainState()
    wallet_state = WalletState()
    mempool_state = MempoolState()
    network_state = NetworkState()
    
    # Step 2: Create service dependencies in order
    # BlockchainService has no service dependencies, only state
    block_validator = BlockValidator()
    blockchain_service = BlockchainService(
        blockchain_state=blockchain_state,
        validator=block_validator,
        event_bus=event_bus
    )
    
    # WalletService depends on BlockchainService
    wallet_service = WalletService(
        wallet_state=wallet_state,
        blockchain_service=blockchain_service,
        event_bus=event_bus
    )
    
    # MiningService depends on BlockchainService
    mining_service = MiningService(
        blockchain_service=blockchain_service,
        event_bus=event_bus
    )
    
    # MempoolService (no dependencies, only state)
    mempool_service = MempoolService(
        mempool_state=mempool_state,
        event_bus=event_bus
    )
    
    # NetworkService (currently a skeleton, no dependencies yet)
    network_service = NetworkService()
    
    # Step 3: Return Services container
    return Services(
        blockchain_service=blockchain_service,
        wallet_service=wallet_service,
        mining_service=mining_service,
        network_service=network_service,
        mempool_service=mempool_service
    )


__all__ = [
    "ServiceResult",
    "Services",
    "get_services",
    "BlockchainService",
    "WalletService",
    "MiningService",
    "NetworkService",
    "MempoolService",
]
