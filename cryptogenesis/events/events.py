"""
Event Type Definitions

Base event class and event type definitions.
"""

from typing import Any, Dict, Optional, TYPE_CHECKING

from cryptogenesis.block import Block
from cryptogenesis.transaction import Transaction
from cryptogenesis.util import get_time

# Import Node from the network module file (not package) to avoid circular import
if TYPE_CHECKING:
    from cryptogenesis.network import Node
else:
    # Import directly from the .py file using importlib to avoid package import
    import importlib.util
    import sys
    import os
    
    # Get the path to network.py (not the package)
    network_file_path = os.path.join(os.path.dirname(__file__), '..', 'network.py')
    network_file_path = os.path.abspath(network_file_path)
    
    spec = importlib.util.spec_from_file_location("network_module", network_file_path)
    network_module = importlib.util.module_from_spec(spec)
    sys.modules['network_module'] = network_module
    spec.loader.exec_module(network_module)
    
    Node = network_module.Node


class Event:
    """
    Base event class.
    
    All events inherit from this class.
    Contains timestamp and data fields.
    """
    
    def __init__(self, data: Optional[Any] = None):
        """
        Initialize event.
        
        Args:
            data: Optional event data
        """
        self.timestamp: float = float(get_time())
        self.data: Optional[Any] = data
    
    def __repr__(self) -> str:
        """String representation for debugging"""
        return f"{self.__class__.__name__}(timestamp={self.timestamp}, data={repr(self.data)})"


class BlockAddedEvent(Event):
    """
    Event published when a block is added to the blockchain.
    """
    
    def __init__(self, block: Block):
        """
        Initialize block added event.
        
        Args:
            block: Block that was added
        """
        super().__init__(data=block)
        self.block: Block = block


class BlockMinedEvent(Event):
    """
    Event published when a block is successfully mined.
    """
    
    def __init__(self, block: Block):
        """
        Initialize block mined event.
        
        Args:
            block: Block that was mined
        """
        super().__init__(data=block)
        self.block: Block = block


class TransactionAddedEvent(Event):
    """
    Event published when a transaction is added to the mempool.
    """
    
    def __init__(self, tx: Transaction):
        """
        Initialize transaction added event.
        
        Args:
            tx: Transaction that was added
        """
        super().__init__(data=tx)
        self.tx: Transaction = tx


class WalletUpdatedEvent(Event):
    """
    Event published when wallet state is updated.
    """
    
    def __init__(self, wallet_data: Dict):
        """
        Initialize wallet updated event.
        
        Args:
            wallet_data: Dictionary containing wallet update information
        """
        super().__init__(data=wallet_data)
        self.wallet_data: Dict = wallet_data


class NetworkPeerConnectedEvent(Event):
    """
    Event published when a peer connects to the network.
    """
    
    def __init__(self, peer: Node):
        """
        Initialize network peer connected event.
        
        Args:
            peer: Node that connected
        """
        super().__init__(data=peer)
        self.peer: Node = peer


class NetworkPeerDisconnectedEvent(Event):
    """
    Event published when a peer disconnects from the network.
    """
    
    def __init__(self, peer: Node):
        """
        Initialize network peer disconnected event.
        
        Args:
            peer: Node that disconnected
        """
        super().__init__(data=peer)
        self.peer: Node = peer

