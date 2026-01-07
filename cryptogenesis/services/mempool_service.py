"""
Mempool Service

Orchestrates mempool operations with state management.
"""

from typing import Optional

from cryptogenesis.events import EventBus, TransactionAddedEvent
from cryptogenesis.services.service_result import ServiceResult
from cryptogenesis.state.mempool_state import MempoolState
from cryptogenesis.transaction import Transaction


class MempoolService:
    """
    Service for mempool operations.

    Orchestrates mempool operations with state management.
    """

    def __init__(
        self,
        mempool_state: MempoolState,
        event_bus: Optional[EventBus] = None,
    ):
        """
        Initialize mempool service.

        Args:
            mempool_state: MempoolState instance for state management
            event_bus: Optional EventBus instance for publishing events
        """
        self.mempool_state = mempool_state
        self.event_bus = event_bus

    def add_transaction(self, tx: Transaction) -> ServiceResult:
        """
        Add transaction to mempool.

        Args:
            tx: Transaction to add

        Returns:
            ServiceResult with success status
        """
        try:
            # Validate transaction
            if not tx.check_transaction():
                return ServiceResult(success=False, error="Transaction validation failed")

            # Check if coinbase (coinbase transactions are only valid in blocks)
            if tx.is_coinbase():
                return ServiceResult(
                    success=False, error="Coinbase transactions cannot be added to mempool"
                )

            # Add to state
            if self.mempool_state.add_transaction(tx):
                # TransactionAddedEvent is already published by mempool_state
                return ServiceResult(success=True, data=tx)
            else:
                return ServiceResult(success=False, error="Transaction already exists in mempool")
        except Exception as e:
            return ServiceResult(
                success=False, error=f"Exception while adding transaction: {str(e)}"
            )

    def get_transaction(self, tx_hash):
        """
        Get transaction from mempool.

        Args:
            tx_hash: Transaction hash

        Returns:
            Transaction if found, None otherwise
        """
        return self.mempool_state.get_transaction(tx_hash)

    def has_transaction(self, tx_hash) -> bool:
        """
        Check if transaction is in mempool.

        Args:
            tx_hash: Transaction hash

        Returns:
            True if transaction is in mempool, False otherwise
        """
        return self.mempool_state.contains(tx_hash)

