"""
Network Manager

Main network manager that coordinates network operations.
Separated from state management - uses NetworkState for state.
Uses services for business logic, never touches GUI directly.
"""

import threading
from typing import Optional

from typing import TYPE_CHECKING

from cryptogenesis.block import Block
from cryptogenesis.events import BlockAddedEvent, EventBus, TransactionAddedEvent
from cryptogenesis.network.peer_manager import PeerManager
from cryptogenesis.network.message_handler import MessageHandler
from cryptogenesis.network.message_sender import MessageSender
from cryptogenesis.services.blockchain_service import BlockchainService
from cryptogenesis.services.service_result import ServiceResult
from cryptogenesis.state.network_state import NetworkState
from cryptogenesis.transaction import Transaction

if TYPE_CHECKING:
    from cryptogenesis.services.mempool_service import MempoolService


class NetworkManager:
    """
    Main network manager.
    
    Coordinates network operations without managing state directly.
    Uses NetworkState for state management and services for business logic.
    All network operations run in separate threads.
    Never touches GUI directly - communicates via events.
    """

    def __init__(
        self,
        event_bus: EventBus,
        blockchain_service: BlockchainService,
        mempool_service: "MempoolService",
        network_state: Optional[NetworkState] = None,
    ):
        """
        Initialize network manager.
        
        Args:
            event_bus: EventBus instance for publishing events
            blockchain_service: BlockchainService instance for adding blocks
            mempool_service: MempoolService instance for adding transactions
            network_state: Optional NetworkState instance (created if not provided)
        """
        self.event_bus = event_bus
        self.blockchain_service = blockchain_service
        self.mempool_service = mempool_service
        
        # Create NetworkState if not provided
        if network_state is None:
            from cryptogenesis.state.network_state import NetworkState
            network_state = NetworkState()
        self.network_state = network_state
        
        # Create sub-managers
        self.peer_manager = PeerManager(network_state=network_state, event_bus=event_bus)
        self.message_handler = MessageHandler(event_bus=event_bus)
        self.message_sender = MessageSender(network_state=network_state, event_bus=event_bus)
        
        # Register message handlers
        self._register_message_handlers()
        
        # Network control
        self._lock = threading.Lock()
        self._is_running = False
        self._listen_thread: Optional[threading.Thread] = None
        self._socket_thread: Optional[threading.Thread] = None
        self._message_thread: Optional[threading.Thread] = None
        self._message_threads: list[threading.Thread] = []
    
    def _register_message_handlers(self):
        """Register handlers for incoming messages"""
        # Register block handler
        self.message_handler.register_handler("block", self._handle_block_message)
        
        # Register transaction handler
        self.message_handler.register_handler("tx", self._handle_transaction_message)
    
    def start(self, port: int = 8333) -> ServiceResult:
        """
        Start network manager in background threads.
        
        Args:
            port: Port to listen on
            
        Returns:
            ServiceResult with success status
        """
        with self._lock:
            if self._is_running:
                return ServiceResult(
                    success=False,
                    error="Network is already running"
                )
            
            try:
                # Start listening thread (for accepting connections)
                self._listen_thread = threading.Thread(
                    target=self._listen_worker,
                    args=(port,),
                    daemon=True
                )
                self._listen_thread.start()
                
                # Start socket handler thread (for socket I/O operations)
                self._socket_thread = threading.Thread(
                    target=self._socket_worker,
                    daemon=True
                )
                self._socket_thread.start()
                
                # Start message processing thread (for processing received messages)
                self._message_thread = threading.Thread(
                    target=self._message_worker,
                    daemon=True
                )
                self._message_thread.start()
                
                self._is_running = True
                return ServiceResult(
                    success=True,
                    data={"port": port, "threads_started": True}
                )
            except Exception as e:
                return ServiceResult(
                    success=False,
                    error=f"Error starting network manager: {str(e)}"
                )
    
    def stop(self) -> None:
        """
        Stop all network threads gracefully.
        
        Disconnects all peers and stops all background threads.
        """
        with self._lock:
            if not self._is_running:
                return
            
            self._is_running = False
            
            # Disconnect all peers
            self.peer_manager.disconnect_all()
            
            # Wait for threads to finish (with timeout)
            threads_to_join = [
                self._listen_thread,
                self._socket_thread,
                self._message_thread,
            ]
            
            for thread in threads_to_join:
                if thread and thread.is_alive():
                    thread.join(timeout=1.0)
            
            for thread in self._message_threads:
                if thread.is_alive():
                    thread.join(timeout=0.5)
            
            self._message_threads.clear()
    
    def is_running(self) -> bool:
        """
        Check if network is active.
        
        Returns:
            True if network is running, False otherwise
        """
        with self._lock:
            return self._is_running
    
    def _listen_worker(self, port: int):
        """
        Listen for incoming connections.
        Runs in a dedicated thread for socket listening.
        All socket operations are in this thread.
        
        Args:
            port: Port to listen on
        """
        # TODO: Implement socket listening
        # This will be implemented in later steps
        # For now, this is a placeholder
        try:
            while self.is_running():
                # Check for shutdown
                import time
                time.sleep(0.1)
        except Exception as e:
            print(f"Error in listen worker: {e}")
            import traceback
            traceback.print_exc()
    
    def _socket_worker(self):
        """
        Socket handler worker.
        Runs in a dedicated thread for socket I/O operations.
        Handles reading from and writing to sockets.
        """
        # TODO: Implement socket I/O handling
        # This will handle select() operations and socket read/write
        # For now, this is a placeholder
        try:
            while self.is_running():
                # Check for shutdown
                import time
                time.sleep(0.1)
        except Exception as e:
            print(f"Error in socket worker: {e}")
            import traceback
            traceback.print_exc()
    
    def _message_worker(self):
        """
        Message processing worker.
        Runs in a separate thread for processing received messages.
        All message processing happens here, communicates via event_bus.
        """
        # TODO: Implement message processing loop
        # This will process messages from nodes and call appropriate handlers
        # For now, this is a placeholder
        try:
            while self.is_running():
                # Check for shutdown
                import time
                time.sleep(0.1)
        except Exception as e:
            print(f"Error in message worker: {e}")
            import traceback
            traceback.print_exc()
    
    def _handle_block_message(self, node, message_data: bytes):
        """
        Handle incoming block message.
        Runs in message processing thread.
        Uses blockchain_service to add block, never touches state directly.
        Communicates via event_bus, never calls GUI methods.
        
        Args:
            node: Node that sent the message
            message_data: Raw message data
        """
        try:
            # TODO: Deserialize block from message_data
            # For now, this is a placeholder
            # block = deserialize_block(message_data)
            
            # When block is received:
            # result = self.process_received_block(block)
            # if not result:
            #     # Publish error event if needed (via event_bus, not GUI)
            #     print(f"Failed to add block: {result.error}")
            
            pass
        except Exception as e:
            print(f"Error handling block message: {e}")
            import traceback
            traceback.print_exc()
    
    def _handle_transaction_message(self, node, message_data: bytes):
        """
        Handle incoming transaction message.
        Runs in message processing thread.
        Uses mempool_service to add transaction, never touches state directly.
        Communicates via event_bus, never calls GUI methods.
        
        Args:
            node: Node that sent the message
            message_data: Raw message data
        """
        try:
            # TODO: Deserialize transaction from message_data
            # For now, this is a placeholder
            # tx = deserialize_transaction(message_data)
            
            # When transaction is received:
            # result = self.process_received_transaction(tx)
            # if not result:
            #     # Publish error event if needed (via event_bus, not GUI)
            #     print(f"Failed to process transaction: {result.error}")
            
            pass
        except Exception as e:
            print(f"Error handling transaction message: {e}")
            import traceback
            traceback.print_exc()
    
    def process_received_block(self, block: Block) -> ServiceResult:
        """
        Process a block received from the network.
        Uses blockchain_service to add block, never touches state directly.
        
        Args:
            block: Block received from network
            
        Returns:
            ServiceResult with success status
        """
        try:
            # Use blockchain_service to add block (never touch state directly)
            result = self.blockchain_service.add_block(block)
            
            if result:
                # BlockAddedEvent is already published by blockchain_service
                # We can publish additional network-specific events here if needed
                pass
            
            return result
        except Exception as e:
            return ServiceResult(
                success=False,
                error=f"Exception processing block: {str(e)}"
            )
    
    def process_received_transaction(self, tx: Transaction) -> ServiceResult:
        """
        Process a transaction received from the network.
        Uses mempool_service to add transaction, never touches state directly.
        Publishes events via event_bus, never calls GUI methods.
        
        Args:
            tx: Transaction received from network
            
        Returns:
            ServiceResult with success status
        """
        try:
            # Use mempool_service to add transaction (never touch state directly)
            result = self.mempool_service.add_transaction(tx)
            
            if result:
                # TransactionAddedEvent is already published by mempool_service
                # Additional network-specific events can be published here if needed
                pass
            else:
                # Publish error event via event_bus (not GUI)
                if self.event_bus:
                    try:
                        # Could publish TransactionRejectedEvent here if we add it
                        pass
                    except Exception as e:
                        print(f"Error publishing event: {e}")
            
            return result
        except Exception as e:
            return ServiceResult(
                success=False,
                error=f"Exception processing transaction: {str(e)}"
            )
