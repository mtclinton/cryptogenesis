"""
Wallet Service

Orchestrates wallet operations with state management.
"""

from typing import List, Optional

from cryptogenesis.crypto import Key
from cryptogenesis.services.blockchain_service import BlockchainService
from cryptogenesis.services.service_result import ServiceResult
from cryptogenesis.state.wallet_state import WalletState
from cryptogenesis.wallet import WalletTx


class WalletService:
    """
    Service for wallet operations.
    
    Orchestrates wallet operations with state management.
    """
    
    def __init__(self, wallet_state: WalletState, blockchain_service: BlockchainService):
        """
        Initialize wallet service.
        
        Args:
            wallet_state: WalletState instance for state management
            blockchain_service: BlockchainService instance for blockchain operations
        """
        self.wallet_state = wallet_state
        self.blockchain_service = blockchain_service
    
    def add_key(self, key: Key) -> ServiceResult:
        """
        Add key to wallet.
        
        Args:
            key: Key object to add
            
        Returns:
            ServiceResult with success status
        """
        try:
            if self.wallet_state.add_key(key):
                return ServiceResult(
                    success=True,
                    data=key
                )
            else:
                return ServiceResult(
                    success=False,
                    error="Key already exists in wallet"
                )
        except Exception as e:
            return ServiceResult(
                success=False,
                error=f"Exception while adding key: {str(e)}"
            )
    
    def get_balance(self) -> int:
        """
        Calculate balance from wallet transactions.
        
        Returns:
            Total wallet balance (sum of credits minus debits)
        """
        try:
            total = 0
            # Get all wallet transactions
            transactions = self.wallet_state.get_all_transactions()
            
            # Calculate balance from each transaction
            for wtx in transactions.values():
                # get_credit() returns outputs that are mine
                # get_debit() returns inputs that are mine (spent)
                total += wtx.get_credit()  # type: ignore[attr-defined]
                total -= wtx.get_debit()  # type: ignore[attr-defined]
            
            return total
        except Exception:
            # Return 0 on error
            return 0
    
    def send_transaction(self, address: str, amount: int) -> ServiceResult:
        """
        Create and send a transaction.
        
        Creates a transaction, signs it, and adds it to mempool.
        Mempool service integration will be added later.
        
        Args:
            address: Recipient address (public key hash)
            amount: Amount to send in satoshi
            
        Returns:
            ServiceResult with transaction data or error
        """
        try:
            # Check if we have any keys
            keys = self.wallet_state.get_all_keys()
            if not keys:
                return ServiceResult(
                    success=False,
                    error="No keys in wallet"
                )
            
            # Check balance
            balance = self.get_balance()
            if balance < amount:
                return ServiceResult(
                    success=False,
                    error=f"Insufficient balance: {balance} < {amount}"
                )
            
            # TODO: Create transaction
            # This is a placeholder - full implementation would:
            # 1. Select UTXOs to spend
            # 2. Create transaction inputs
            # 3. Create transaction outputs
            # 4. Sign transaction inputs
            # 5. Add to mempool via mempool_service (to be added later)
            
            return ServiceResult(
                success=False,
                error="Transaction creation not yet implemented (requires UTXO selection and signing)"
            )
        except Exception as e:
            return ServiceResult(
                success=False,
                error=f"Exception while sending transaction: {str(e)}"
            )
    
    def get_transactions(self) -> List[WalletTx]:
        """
        Get all wallet transactions.
        
        Returns:
            List of WalletTx objects
        """
        try:
            transactions = self.wallet_state.get_all_transactions()
            return list(transactions.values())
        except Exception:
            return []
    
    def load_from_storage(self) -> ServiceResult:
        """
        Load wallet from storage (disk/memory).
        
        For now, this is a placeholder that returns success.
        In a full implementation, this would load keys and transactions from disk.
        
        Returns:
            ServiceResult with success status
        """
        try:
            # For now, wallet is in-memory and already loaded
            # In a full implementation, this would:
            # 1. Load keys from disk
            # 2. Load transactions from disk
            # 3. Update wallet_state
            
            # Check if we have any keys or transactions
            keys = self.wallet_state.get_all_keys()
            transactions = self.wallet_state.get_all_transactions()
            
            if not keys and not transactions:
                return ServiceResult(
                    success=False,
                    error="No wallet data found in storage"
                )
            
            return ServiceResult(
                success=True,
                data={
                    "keys": len(keys),
                    "transactions": len(transactions)
                }
            )
        except Exception as e:
            return ServiceResult(
                success=False,
                error=f"Exception while loading from storage: {str(e)}"
            )
