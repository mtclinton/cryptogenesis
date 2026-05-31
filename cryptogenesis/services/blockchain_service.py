"""
Blockchain Service

Orchestrates blockchain operations with state management.
"""

from typing import Optional, Tuple

from cryptogenesis.block import Block
from cryptogenesis.chain import BlockChain, get_chain
from cryptogenesis.events import BlockAddedEvent, EventBus
from cryptogenesis.services.service_result import ServiceResult
from cryptogenesis.state.blockchain_state import BlockchainState
from cryptogenesis.uint256 import uint256


class BlockValidator:
    """
    Validator for blocks.
    
    Wraps the existing chain validation logic.
    """
    
    def __init__(self, chain: Optional[BlockChain] = None):
        """
        Initialize block validator.
        
        Args:
            chain: BlockChain instance to use for validation (defaults to get_chain())
        """
        self.chain = chain if chain is not None else get_chain()
    
    def validate(self, block: Block) -> Tuple[bool, Optional[str]]:
        """
        Validate a block.
        
        Args:
            block: Block to validate
            
        Returns:
            Tuple of (success: bool, error: Optional[str])
        """
        try:
            # Use the chain's accept_block logic for validation
            # Note: This will also add the block to the chain, so we need to be careful
            # For now, we'll check if block already exists first
            block_hash = block.get_hash()
            
            if self.chain.has_block(block_hash):
                return False, "Block already exists in chain"
            
            # Validate using accept_block
            # Note: accept_block does full validation including:
            # - Duplicate check
            # - Previous block existence
            # - Timestamp validation
            # - Proof of work validation
            if self.chain.accept_block(block):
                return True, None
            else:
                return False, "Block validation failed"
        except Exception as e:
            return False, f"Validation error: {str(e)}"


class BlockchainService:
    """
    Service for blockchain operations.
    
    Orchestrates blockchain operations with state management.
    """
    
    def __init__(
        self,
        blockchain_state: BlockchainState,
        validator: Optional[BlockValidator] = None,
        event_bus: Optional[EventBus] = None,
    ):
        """
        Initialize blockchain service.
        
        Args:
            blockchain_state: BlockchainState instance for state management
            validator: BlockValidator instance (defaults to new validator with default chain)
            event_bus: Optional EventBus instance for publishing events
        """
        self.blockchain_state = blockchain_state
        self.validator = validator  # retained for compatibility; no longer used
        self.event_bus = event_bus
    
    def add_block(self, block: Block) -> ServiceResult:
        """
        Add block to blockchain.
        
        Validates the block, adds it to state if valid, and returns result.
        Event publishing will be added in Phase 3.
        
        Args:
            block: Block to add
            
        Returns:
            ServiceResult with success status and data/error
        """
        try:
            # Single write path: the state facade accepts/connects the block on
            # the one chain engine. (No separate validate -> accept_block step,
            # which previously double-processed and wrote two stores.)
            if not self.blockchain_state.add_block(block):
                return ServiceResult(
                    success=False,
                    error="Block rejected by chain (invalid, duplicate, or orphan)",
                )

            # Publish BlockAddedEvent once, from the service layer.
            if self.event_bus:
                try:
                    self.event_bus.publish(BlockAddedEvent(block))
                except Exception as e:
                    print(f"Error publishing BlockAddedEvent: {e}")

            return ServiceResult(success=True, data=block)
        except Exception as e:
            return ServiceResult(
                success=False,
                error=f"Exception while adding block: {str(e)}"
            )
    
    def get_best_height(self) -> int:
        """Get current best block height. Delegates to blockchain_state."""
        return self.blockchain_state.get_best_height()

    def get_best_hash(self) -> uint256:
        """Get the best block hash. Delegates to blockchain_state."""
        return self.blockchain_state.get_best_hash()

    def get_best_index(self):
        """Get the best BlockIndex (linked, height-aware) for chain walks."""
        return self.blockchain_state.get_best_index()

    def get_block(self, block_hash: uint256) -> Optional[Block]:
        """
        Get block by hash.
        
        Delegates to blockchain_state.
        
        Args:
            block_hash: Hash of block to retrieve
            
        Returns:
            Block if found, None otherwise
        """
        return self.blockchain_state.get_block(block_hash)
    
    def load_from_storage(self) -> ServiceResult:
        """
        Load blockchain from storage (disk/memory).
        
        For now, this is a placeholder that returns success.
        In a full implementation, this would load blocks from disk.
        
        Returns:
            ServiceResult with success status
        """
        try:
            # For now, blockchain is in-memory and already loaded
            # In a full implementation, this would:
            # 1. Load block index from disk
            # 2. Load blocks from disk
            # 3. Reconstruct UTXO set
            # 4. Update blockchain_state
            
            # Check if we have any blocks
            best_height = self.blockchain_state.get_best_height()
            
            if best_height < 0:
                return ServiceResult(
                    success=False,
                    error="No blocks found in storage"
                )
            
            return ServiceResult(
                success=True,
                data={"height": best_height, "best_hash": self.blockchain_state.get_best_hash()}
            )
        except Exception as e:
            return ServiceResult(
                success=False,
                error=f"Exception while loading from storage: {str(e)}"
            )
