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

                # Publish event that mining started (wallet will be updated)
                if self.event_bus:
                    try:
                        from cryptogenesis.events import WalletUpdatedEvent
                        self.event_bus.publish(WalletUpdatedEvent({"action": "mining_started", "node_id": node_id}))
                    except Exception as e:
                        print(f"Warning: Failed to publish mining started event: {e}")

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

        Uses different miner based on network mode:
        - Private network: bitcoin_miner_private_network (uses services directly)
        - Mainnet: bitcoin_miner (uses legacy chain.process_block)

        Args:
            node_id: Optional node ID for deterministic key generation
        """
        try:
            from cryptogenesis.network import get_network_mode

            print("Mining worker thread started")

            if get_network_mode() == "private":
                # For private network, use the refactored miner that uses services
                from cryptogenesis.mining import bitcoin_miner_private_network
                bitcoin_miner_private_network(
                    node_id=node_id,
                    blockchain_service=self.blockchain_service,
                    event_bus=self.event_bus
                )
            else:
                # For mainnet, use the original bitcoin_miner (to be refactored later)
                bitcoin_miner(node_id=node_id)

            print("Mining worker thread finished")
        except Exception as e:
            # Log error but don't crash the service
            print(f"Error in mining worker: {e}")
            import traceback
            traceback.print_exc()
        finally:
            # Ensure mining flag is reset when thread exits
            print("Mining worker thread cleanup")
            with self._mining_lock:
                self._is_mining = False
                set_generate_bitcoins(False)
                print("Mining worker thread cleanup completed")
