"""
Mining Service

Orchestrates mining operations with state management.
"""

import threading
from typing import Optional

from cryptogenesis.events import BlockMinedEvent, EventBus
from cryptogenesis.services.blockchain_service import BlockchainService
from cryptogenesis.services.service_result import ServiceResult
from cryptogenesis.mining import bitcoin_miner, get_generate_bitcoins, set_generate_bitcoins


class MiningService:
    """
    Service for mining operations.
    
    Orchestrates mining operations with state management.
    Runs mining in a separate thread.
    """
    
    def __init__(self, blockchain_service: BlockchainService, event_bus: Optional[EventBus] = None):
        """
        Initialize mining service.
        
        Args:
            blockchain_service: BlockchainService instance for adding blocks
            event_bus: Optional EventBus instance for publishing events
        """
        self.blockchain_service = blockchain_service
        self.event_bus = event_bus
        self._mining_thread: Optional[threading.Thread] = None
        self._mining_lock = threading.Lock()
        self._is_mining = False
    
    def start_mining(self, node_id: Optional[int] = None) -> ServiceResult:
        """
        Start mining in background thread.
        
        Args:
            node_id: Optional node ID for deterministic key generation
            
        Returns:
            ServiceResult with success status
        """
        try:
            with self._mining_lock:
                if self._is_mining:
                    return ServiceResult(
                        success=False,
                        error="Mining is already running"
                    )
                
                # Set mining flag
                set_generate_bitcoins(True)
                self._is_mining = True
                
                # Start mining thread
                # Note: We use a wrapper function to integrate with blockchain_service
                self._mining_thread = threading.Thread(
                    target=self._mining_worker,
                    args=(node_id,),
                    daemon=True
                )
                self._mining_thread.start()
                
                return ServiceResult(
                    success=True,
                    data={"thread_started": True}
                )
        except Exception as e:
            with self._mining_lock:
                self._is_mining = False
                set_generate_bitcoins(False)
            return ServiceResult(
                success=False,
                error=f"Exception while starting mining: {str(e)}"
            )
    
    def stop_mining(self) -> None:
        """
        Stop mining thread.
        
        Sets the mining flag to False, which will cause the mining loop to exit.
        """
        try:
            with self._mining_lock:
                if not self._is_mining:
                    return
                
                # Set flag to stop mining
                set_generate_bitcoins(False)
                self._is_mining = False
        except Exception:
            # Ensure flag is set even if error occurs
            set_generate_bitcoins(False)
            self._is_mining = False
    
    def is_mining(self) -> bool:
        """
        Check if mining is active.
        
        Returns:
            True if mining is active, False otherwise
        """
        try:
            with self._mining_lock:
                return self._is_mining and get_generate_bitcoins()
        except Exception:
            return False
    
    def _mining_worker(self, node_id: Optional[int] = None):
        """
        Mining worker function that runs in background thread.
        
        This wraps the existing bitcoin_miner() function.
        
        NOTE: Currently, bitcoin_miner() uses chain.process_block() directly.
        In the future, the mining code should be refactored to call
        blockchain_service.add_block() when blocks are found, and publish
        BlockMinedEvent through the event bus.
        
        Args:
            node_id: Optional node ID for deterministic key generation
        """
        try:
            # The bitcoin_miner() function handles:
            # - Block creation
            # - Proof-of-work
            # - Block processing via chain.process_block()
            #
            # TODO: Refactor bitcoin_miner() to use blockchain_service.add_block()
            # instead of chain.process_block() directly. This requires:
            # 1. Extracting block creation and mining logic
            # 2. Calling blockchain_service.add_block() when block is found
            # 3. Publishing BlockMinedEvent through event_bus after successful mining
            #
            # When refactored, the code should:
            # - Call blockchain_service.add_block(block) when block is found
            # - If successful, publish BlockMinedEvent(block) via event_bus
            # - This ensures BlockMinedEvent is published after state update succeeds
            #
            # For now, we run bitcoin_miner() as-is, which still works correctly
            # but doesn't use the service layer for block addition or event publishing.
            
            bitcoin_miner(node_id=node_id)
        except Exception as e:
            # Log error but don't crash the service
            print(f"Error in mining worker: {e}")
            import traceback
            traceback.print_exc()
        finally:
            # Ensure mining flag is reset when thread exits
            with self._mining_lock:
                self._is_mining = False
                set_generate_bitcoins(False)
