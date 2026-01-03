"""
GUI Controller

Controller for GUI that handles business logic and coordinates between
views and services. Separated from view components.
"""

import threading
import time
from datetime import datetime
from typing import Optional

# Try to import wxPython
try:
    import wx
    WX_AVAILABLE = True
except ImportError:
    wx = None
    WX_AVAILABLE = False

from cryptogenesis.events import (
    BlockAddedEvent,
    EventBus,
    NetworkPeerConnectedEvent,
    NetworkPeerDisconnectedEvent,
    TransactionAddedEvent,
    WalletUpdatedEvent,
)
from cryptogenesis.services import Services
from cryptogenesis.transaction import COIN
from cryptogenesis.ui.main_window import MainWindow
from cryptogenesis.wallet import WalletTx


if not WX_AVAILABLE:
    # Stub classes if wxPython is not available
    class GUIController:
        pass
else:

    class GUIController:
        """
        Controller for GUI that handles business logic.
        Coordinates between views and services.
        Never accesses state directly, only through services.
        """

        def __init__(
            self,
            main_window: MainWindow,
            services: Services,
            event_bus: EventBus
        ):
            """
            Initialize GUI controller.
            
            Args:
                main_window: MainWindow instance
                services: Services container
                event_bus: EventBus instance
            """
            self.main_window = main_window
            self.services = services
            self.event_bus = event_bus
            
            # Bind event handlers
            self._bind_events()
            
            # Subscribe to events from event_bus
            self._subscribe_to_events()
            
            # Initialize views with data from services
            self._initial_refresh()

        def _bind_events(self):
            """Bind GUI event handlers"""
            # Menu events
            if self.main_window.menu_initialize:
                self.main_window.bind_menu_event(
                    self.main_window.menu_initialize.GetId(),
                    self._on_initialize_system
                )
            if self.main_window.menu_refresh:
                self.main_window.bind_menu_event(
                    self.main_window.menu_refresh.GetId(),
                    self._on_refresh
                )
            if self.main_window.menu_network:
                self.main_window.bind_menu_event(
                    self.main_window.menu_network.GetId(),
                    self._on_network
                )
            if self.main_window.menu_generate:
                self.main_window.bind_menu_event(
                    self.main_window.menu_generate.GetId(),
                    self._on_generate_coins
                )
            
            # Toolbar events
            if hasattr(self.main_window, 'send_tool_id'):
                self.main_window.bind_tool_event(
                    self.main_window.send_tool_id,
                    self._on_send
                )
            if hasattr(self.main_window, 'addr_tool_id'):
                self.main_window.bind_tool_event(
                    self.main_window.addr_tool_id,
                    self._on_address_book
                )
            
            # Close event
            self.main_window.Bind(wx.EVT_CLOSE, self._on_close)
        
        def _subscribe_to_events(self):
            """Subscribe to events from event_bus"""
            if self.event_bus:
                self.event_bus.subscribe(BlockAddedEvent, self._on_block_added)
                self.event_bus.subscribe(TransactionAddedEvent, self._on_transaction_added)
                self.event_bus.subscribe(WalletUpdatedEvent, self._on_wallet_updated)
                self.event_bus.subscribe(NetworkPeerConnectedEvent, self._on_peer_connected)
                self.event_bus.subscribe(NetworkPeerDisconnectedEvent, self._on_peer_disconnected)
        
        def _initial_refresh(self):
            """Initial refresh of views with data from services"""
            # Refresh on main thread
            wx.CallAfter(self._refresh_wallet)
            wx.CallAfter(self._refresh_transactions)

        def _on_block_added(self, event: BlockAddedEvent):
            """
            Handle BlockAddedEvent from event_bus.
            Uses wx.CallAfter to update GUI on main thread.
            """
            wx.CallAfter(self._refresh_wallet)
            wx.CallAfter(self._refresh_transactions)
            wx.CallAfter(self._update_status)
        
        def _on_transaction_added(self, event: TransactionAddedEvent):
            """
            Handle TransactionAddedEvent from event_bus.
            Uses wx.CallAfter to update GUI on main thread.
            """
            wx.CallAfter(self._refresh_transactions)
            wx.CallAfter(self._refresh_wallet)
        
        def _on_wallet_updated(self, event: WalletUpdatedEvent):
            """
            Handle WalletUpdatedEvent from event_bus.
            Uses wx.CallAfter to update GUI on main thread.
            """
            wx.CallAfter(self._refresh_wallet)
            wx.CallAfter(self._refresh_transactions)

        def _on_peer_connected(self, event: NetworkPeerConnectedEvent):
            """
            Handle NetworkPeerConnectedEvent from event_bus.
            Uses wx.CallAfter to update GUI on main thread.
            """
            wx.CallAfter(self._update_status)

        def _on_peer_disconnected(self, event: NetworkPeerDisconnectedEvent):
            """
            Handle NetworkPeerDisconnectedEvent from event_bus.
            Uses wx.CallAfter to update GUI on main thread.
            """
            wx.CallAfter(self._update_status)

        def _on_initialize_system(self, event):
            """Handle Initialize System menu item"""
            # Run initialization in background thread
            def init_thread():
                try:
                    # Load blockchain from storage
                    result = self.services.blockchain_service.load_from_storage()
                    if not result:
                        wx.CallAfter(
                            self.main_window.set_status_text,
                            f"Initialization error: {result.error}"
                        )
                        return
                    
                    # Load wallet from storage
                    result = self.services.wallet_service.load_from_storage()
                    if not result:
                        wx.CallAfter(
                            self.main_window.set_status_text,
                            f"Wallet load error: {result.error}"
                        )
                    
                    # Update UI on main thread
                    wx.CallAfter(self._refresh_wallet)
                    wx.CallAfter(self._refresh_transactions)
                    wx.CallAfter(self._update_status)
                    wx.CallAfter(
                        self.main_window.set_status_text,
                        "System initialized"
                    )
                    self.main_window.system_initialized = True
                except Exception as e:
                    wx.CallAfter(
                        self.main_window.set_status_text,
                        f"Initialization error: {str(e)}"
                    )
            
            threading.Thread(target=init_thread, daemon=True).start()
            self.main_window.set_status_text("Initializing system...")

        def _on_refresh(self, event):
            """Handle Refresh menu item"""
            self._refresh_wallet()
            self._refresh_transactions()
            self._update_status()

        def _on_network(self, event):
            """Handle Start Network menu item"""
            is_checked = self.main_window.menu_network.IsChecked()
            
            def network_thread():
                try:
                    if is_checked:
                        # Start network
                        # TODO: NetworkService.start() to be implemented
                        if hasattr(self.services.network_service, 'start'):
                            result = self.services.network_service.start()
                            if result:
                                wx.CallAfter(
                                    self.main_window.set_status_text,
                                    "Network started"
                                )
                            else:
                                wx.CallAfter(
                                    self.main_window.set_status_text,
                                    f"Network start error: {result.error}"
                                )
                                wx.CallAfter(
                                    self.main_window.menu_network.Check,
                                    False
                                )
                        else:
                            wx.CallAfter(
                                self.main_window.set_status_text,
                                "Network service not yet implemented"
                            )
                            wx.CallAfter(
                                self.main_window.menu_network.Check,
                                False
                            )
                    else:
                        # Stop network
                        if hasattr(self.services.network_service, 'stop'):
                            self.services.network_service.stop()
                            wx.CallAfter(
                                self.main_window.set_status_text,
                                "Network stopped"
                            )
                        else:
                            wx.CallAfter(
                                self.main_window.set_status_text,
                                "Network service not yet implemented"
                            )
                except Exception as e:
                    wx.CallAfter(
                        self.main_window.set_status_text,
                        f"Network error: {str(e)}"
                    )
            
            threading.Thread(target=network_thread, daemon=True).start()

        def _on_generate_coins(self, event):
            """Handle Generate Coins menu item"""
            is_checked = self.main_window.menu_generate.IsChecked()
            
            def mining_thread():
                try:
                    if is_checked:
                        # Start mining
                        result = self.services.mining_service.start_mining()
                        if result:
                            wx.CallAfter(
                                self.main_window.set_status_text,
                                "Mining started"
                            )
                        else:
                            wx.CallAfter(
                                self.main_window.set_status_text,
                                f"Mining start error: {result.error}"
                            )
                            wx.CallAfter(
                                self.main_window.menu_generate.Check,
                                False
                            )
                    else:
                        # Stop mining
                        self.services.mining_service.stop_mining()
                        wx.CallAfter(
                            self.main_window.set_status_text,
                            "Mining stopped"
                        )
                except Exception as e:
                    wx.CallAfter(
                        self.main_window.set_status_text,
                        f"Mining error: {str(e)}"
                    )
            
            threading.Thread(target=mining_thread, daemon=True).start()

        def _on_send(self, event):
            """Handle Send toolbar button"""
            # TODO: Open send dialog (to be implemented)
            self.main_window.set_status_text("Send dialog not yet implemented")

        def _on_address_book(self, event):
            """Handle Address Book toolbar button"""
            # TODO: Open address book dialog (to be implemented)
            self.main_window.set_status_text("Address book not yet implemented")

        def _on_close(self, event):
            """Handle window close event"""
            # Stop mining and network
            try:
                self.services.mining_service.stop_mining()
                if hasattr(self.services.network_service, 'stop'):
                    self.services.network_service.stop()
            except Exception:
                pass  # Ignore errors during shutdown
            
            self.main_window.Destroy()
        
        def _refresh_wallet(self):
            """Refresh wallet view using services"""
            try:
                wallet_view = self.main_window.get_wallet_view()
                if not wallet_view:
                    return

                # Get balance from service
                balance = self.services.wallet_service.get_balance()
                balance_str = self._format_money(balance)
                wallet_view.update_balance(balance_str)

                # Get address from service
                address = self._get_wallet_address()
                wallet_view.update_address(address)
            except Exception as e:
                # Handle errors gracefully
                print(f"Error refreshing wallet: {e}")
        
        def _refresh_transactions(self):
            """Refresh transaction view using services"""
            try:
                tx_view = self.main_window.get_transaction_view()
                if not tx_view:
                    return
                
                # Clear existing transactions
                tx_view.clear()
                
                # Get transactions from service
                transactions = self.services.wallet_service.get_transactions()
                
                # Sort by time (newest first)
                sorted_txs = sorted(
                    transactions,
                    key=lambda wtx: getattr(wtx, 'n_time_received', 0),
                    reverse=True
                )
                
                # Add transactions to view
                for wtx in sorted_txs:
                    date_str = self._format_date(wtx)
                    tx_type = self._get_transaction_type(wtx)
                    address = self._get_transaction_address(wtx)
                    amount = self._format_money(self._get_transaction_amount(wtx))
                    status = self._get_transaction_status(wtx)
                    
                    tx_view.add_transaction(
                        date=date_str,
                        tx_type=tx_type,
                        address=address,
                        amount=amount,
                        status=status
                    )
            except Exception as e:
                # Handle errors gracefully
                print(f"Error refreshing transactions: {e}")

        def _update_status(self):
            """Update status bar"""
            try:
                height = self.services.blockchain_service.get_best_height()
                is_mining = self.services.mining_service.is_mining()
                mining_status = "Mining" if is_mining else "Not mining"
                peer_count = self._get_peer_count()
                status_text = f"Height: {height} | {mining_status} | Peers: {peer_count}"
                self.main_window.set_status_text(status_text)
            except Exception as e:
                print(f"Error updating status: {e}")

        def _get_peer_count(self) -> int:
            """Get current peer count from network state"""
            try:
                if hasattr(self.services.network_service, 'network_manager') and self.services.network_service.network_manager:
                    return self.services.network_service.network_manager.network_state.get_peer_count()
                return 0
            except Exception:
                return 0
        
        def _format_money(self, amount: int) -> str:
            """
            Format money amount for display.
            
            Args:
                amount: Amount in satoshi
                
            Returns:
                Formatted string (e.g., "1.23 BTC")
            """
            try:
                btc = amount / COIN
                return f"{btc:.2f}"
            except Exception:
                return "0.00"
        
        def _get_wallet_address(self) -> str:
            """
            Get wallet address from service.
            
            Returns:
                Address string or "No address"
            """
            try:
                # Get address from service (never access state directly)
                address = self.services.wallet_service.get_address()
                if address:
                    return address
                return "No address"
            except Exception as e:
                print(f"Error getting wallet address: {e}")
                return "Error"
        
        def _format_date(self, wtx: WalletTx) -> str:
            """Format transaction date"""
            try:
                time_received = getattr(wtx, 'n_time_received', None)
                if time_received:
                    dt = datetime.fromtimestamp(time_received)
                    return dt.strftime("%Y-%m-%d %H:%M")
                return "Unknown"
            except Exception:
                return "Unknown"
        
        def _get_transaction_type(self, wtx: WalletTx) -> str:
            """Get transaction type (Send/Receive)"""
            try:
                credit = wtx.get_credit()  # type: ignore[attr-defined]
                debit = wtx.get_debit()  # type: ignore[attr-defined]
                if credit > 0 and debit == 0:
                    return "Receive"
                elif debit > 0:
                    return "Send"
                return "Unknown"
            except Exception:
                return "Unknown"
        
        def _get_transaction_address(self, wtx: WalletTx) -> str:
            """Get transaction address"""
            try:
                # Simplified - would need to extract from outputs/inputs
                return "N/A"
            except Exception:
                return "N/A"
        
        def _get_transaction_amount(self, wtx: WalletTx) -> int:
            """Get transaction amount"""
            try:
                credit = wtx.get_credit()  # type: ignore[attr-defined]
                debit = wtx.get_debit()  # type: ignore[attr-defined]
                return credit - debit
            except Exception:
                return 0
        
        def _get_transaction_status(self, wtx: WalletTx) -> str:
            """Get transaction status"""
            try:
                # Check if transaction is confirmed
                if hasattr(wtx, 'hash_block') and wtx.hash_block:
                    return "Confirmed"
                return "Pending"
            except Exception:
                return "Unknown"

