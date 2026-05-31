"""
Wallet State Manager

Single source of truth for wallet data: a thin thread-safe facade over the one
global wallet (cryptogenesis.wallet -- map_keys/map_pub_keys/map_wallet). The
previous parallel _keys/_transactions dicts were a second store the live path
never wrote (mining and the node use the global wallet directly), so facading
the one engine removes the divergence and the notify-observers-under-lock.
"""

from typing import Dict, Optional

from cryptogenesis.crypto import Key
from cryptogenesis.uint256 import uint160, uint256
from cryptogenesis.wallet import WalletTx


class WalletState:
    """Thread-safe facade over the single global wallet."""

    def __init__(self):
        # The global wallet has its own locks (wallet.keys_lock / wallet.wallet_lock);
        # this facade simply delegates to it.
        pass

    def add_key(self, key: Key) -> bool:
        from cryptogenesis import wallet

        try:
            return wallet.add_key(key)
        except Exception:
            return False

    def has_key(self, pubkey_hash: bytes) -> bool:
        from cryptogenesis import wallet

        with wallet.keys_lock:
            return uint160(pubkey_hash) in wallet.map_pub_keys

    def get_all_keys(self) -> Dict[uint160, Key]:
        """Reconstruct {hash160 -> Key} from the global key maps."""
        from cryptogenesis import wallet

        out: Dict[uint160, Key] = {}
        with wallet.keys_lock:
            items = list(wallet.map_pub_keys.items())
            privkeys = dict(wallet.map_keys)
        for h160, pubkey in items:
            privkey = privkeys.get(pubkey)
            if privkey is None:
                continue
            k = Key()
            try:
                k.set_privkey(privkey)
            except Exception:
                continue
            out[h160] = k
        return out

    def add_transaction(self, wtx: WalletTx) -> bool:
        from cryptogenesis import wallet

        return wallet.add_to_wallet(wtx)

    def get_transaction(self, tx_hash: uint256) -> Optional[WalletTx]:
        from cryptogenesis import wallet

        return wallet.get_wallet().get(tx_hash)

    def has_transaction(self, tx_hash: uint256) -> bool:
        from cryptogenesis import wallet

        return tx_hash in wallet.get_wallet()

    def get_all_transactions(self) -> Dict[uint256, WalletTx]:
        from cryptogenesis import wallet

        return dict(wallet.get_wallet())
