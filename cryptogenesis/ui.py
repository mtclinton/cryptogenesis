"""
Copyright (c) 2009 Satoshi Nakamoto
Distributed under the MIT/X11 software license

Bitcoin v0.1 Python GUI Implementation
Matches CMainFrame and related dialogs from Bitcoin v0.1
"""

import threading
import time
from datetime import datetime
from typing import Callable, Optional

# Try to import wxPython
try:
    import wx
    import wx.adv
    WX_AVAILABLE = True
except ImportError:
    wx = None
    wx.adv = None
    WX_AVAILABLE = False

from cryptogenesis import get_balance, get_wallet
from cryptogenesis.chain import get_chain
from cryptogenesis.crypto import Key, hash160
from cryptogenesis.mining import get_generate_bitcoins, set_generate_bitcoins, start_mining
from cryptogenesis.network import stop_node
from cryptogenesis.transaction import COIN, COINBASE_MATURITY
from cryptogenesis.util import format_money, parse_money
from cryptogenesis.wallet import (
    WalletTx,
    generate_new_key,
    get_wallet_address,
    send_money,
)


def pubkey_to_address(pubkey: bytes) -> str:
    """Convert public key to address (simplified - would use base58 in production)"""
    pubkey_hash = hash160(pubkey)
    # In production, this would use base58 encoding
    # For now, return hex representation
    return pubkey_hash.hex()[:40]


if not WX_AVAILABLE:
    # Create stub classes if wxPython is not available
    class MainFrame:
            pass
    class SendDialog:
            pass
    class AddressBookDialog:
            pass
    class OptionsDialog:
            pass
    class BitcoinApp:
        def __init__(self, *args, **kwargs):
            raise ImportError("wxPython is required for GUI. Install with: pip install wxPython")
else:

    class MainFrame(wx.Frame):
        """Main window matching CMainFrame from Bitcoin v0.1"""

        def __init__(self, parent):
            super().__init__(parent, title="Bitcoin", size=(900, 700))
            self.f_refresh_list_ctrl = True
            self.f_refresh_list_ctrl_running = False
            self.pindex_best_last = None

            # Create menu bar
            self.create_menu_bar()

            # Create toolbar
            self.create_toolbar()

            # Create main panel
            panel = wx.Panel(self)
            sizer = wx.BoxSizer(wx.VERTICAL)

            # Balance display (top)
            balance_panel = self.create_balance_panel(panel)
            sizer.Add(balance_panel, 0, wx.EXPAND | wx.ALL, 5)

            # Address display
            address_panel = self.create_address_panel(panel)
            sizer.Add(address_panel, 0, wx.EXPAND | wx.ALL, 5)

            # Transaction list
            tx_list = self.create_transaction_list(panel)
            sizer.Add(tx_list, 1, wx.EXPAND | wx.ALL, 5)

            # Status bar
            self.CreateStatusBar()
            self.update_status()

            panel.SetSizer(sizer)

            # Refresh timer - DON'T start until system is initialized
            self.timer = wx.Timer(self)
            self.Bind(wx.EVT_TIMER, self.on_timer)
            # Timer will be started manually after initialization
            self.system_initialized = False

            # Event handlers
            self.Bind(wx.EVT_CLOSE, self.on_close)

            # Don't refresh immediately - let the window be shown first
            # Refresh will happen via timer after window is responsive

        def create_menu_bar(self):
            """Create menu bar matching Bitcoin v0.1"""
            menubar = wx.MenuBar()

            # File menu
            file_menu = wx.Menu()
            file_menu.Append(wx.ID_EXIT, "E&xit\tCtrl+Q", "Exit application")
            menubar.Append(file_menu, "&File")

            # Options menu
            options_menu = wx.Menu()
            self.menu_initialize = options_menu.Append(
                wx.ID_ANY, "&Initialize System", "Initialize Bitcoin system"
            )
            self.menu_refresh = options_menu.Append(
                wx.ID_ANY, "&Refresh", "Refresh wallet and balance"
            )
            self.menu_network = options_menu.Append(
                wx.ID_ANY, "&Start Network", "Start Bitcoin network node", kind=wx.ITEM_CHECK
            )
            self.menu_generate = options_menu.Append(
                wx.ID_ANY, "&Generate Coins", "Generate bitcoins", kind=wx.ITEM_CHECK
            )
            options_menu.Append(wx.ID_PREFERENCES, "&Options...", "Settings")
            menubar.Append(options_menu, "&Options")

            # Help menu
            help_menu = wx.Menu()
            help_menu.Append(wx.ID_ABOUT, "&About...", "About Bitcoin")
            menubar.Append(help_menu, "&Help")

            self.SetMenuBar(menubar)

            # Bind events
            self.Bind(wx.EVT_MENU, self.on_exit, id=wx.ID_EXIT)
            self.Bind(wx.EVT_MENU, self.on_initialize_system, self.menu_initialize)
            self.Bind(wx.EVT_MENU, self.on_refresh, self.menu_refresh)
            self.Bind(wx.EVT_MENU, self.on_network, self.menu_network)
            self.Bind(wx.EVT_MENU, self.on_generate_coins, self.menu_generate)
            self.Bind(wx.EVT_MENU, self.on_options, id=wx.ID_PREFERENCES)
            self.Bind(wx.EVT_MENU, self.on_about, id=wx.ID_ABOUT)
            
            # Network is not started by default
            self.network_running = False

            # Set initial generate state (only if system is initialized)
            try:
                if hasattr(self, 'system_initialized') and self.system_initialized:
                    self.menu_generate.Check(get_generate_bitcoins())
            except Exception:
                pass

        def create_toolbar(self):
            """Create toolbar with Send and Address Book buttons"""
            toolbar = self.CreateToolBar()

            # Send button
            send_tool = toolbar.AddTool(
            wx.ID_ANY,
            "Send",
            wx.ArtProvider.GetBitmap(wx.ART_GO_FORWARD),
            "Send bitcoins",
            )

            # Address Book button
            addr_tool = toolbar.AddTool(
            wx.ID_ANY,
            "Address Book",
            wx.ArtProvider.GetBitmap(wx.ART_HELP_BOOK),
            "Address Book",
            )

            toolbar.Realize()

            # Bind events
            self.Bind(wx.EVT_TOOL, self.on_send, send_tool)
            self.Bind(wx.EVT_TOOL, self.on_address_book, addr_tool)

        def create_balance_panel(self, parent):
            """Create balance display panel"""
            panel = wx.Panel(parent)
            sizer = wx.BoxSizer(wx.HORIZONTAL)

            label = wx.StaticText(panel, label="Balance:")
            label.SetFont(
            wx.Font(12, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_BOLD)
            )
            sizer.Add(label, 0, wx.ALL, 5)

            self.balance_text = wx.StaticText(panel, label="0.00 BTC")
            self.balance_text.SetFont(
            wx.Font(12, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_BOLD)
            )
            sizer.Add(self.balance_text, 0, wx.ALL, 5)

            panel.SetSizer(sizer)
            return panel

        def create_address_panel(self, parent):
            """Create address display panel"""
            panel = wx.Panel(parent)
            sizer = wx.BoxSizer(wx.HORIZONTAL)

            label = wx.StaticText(panel, label="Your Address:")
            sizer.Add(label, 0, wx.ALL, 5)

            self.address_text = wx.TextCtrl(panel, style=wx.TE_READONLY)
            sizer.Add(self.address_text, 1, wx.EXPAND | wx.ALL, 5)

            copy_btn = wx.Button(panel, label="Copy")
            copy_btn.Bind(wx.EVT_BUTTON, self.on_copy_address)
            sizer.Add(copy_btn, 0, wx.ALL, 5)

            change_btn = wx.Button(panel, label="Change")
            change_btn.Bind(wx.EVT_BUTTON, self.on_change_address)
            sizer.Add(change_btn, 0, wx.ALL, 5)

            panel.SetSizer(sizer)
            return panel

        def create_transaction_list(self, parent):
            """Create transaction list control"""
            list_ctrl = wx.ListCtrl(parent, style=wx.LC_REPORT | wx.LC_SINGLE_SEL)

            # Add columns matching Bitcoin v0.1
            list_ctrl.InsertColumn(0, "Date", width=120)
            list_ctrl.InsertColumn(1, "Type", width=80)
            list_ctrl.InsertColumn(2, "Address", width=200)
            list_ctrl.InsertColumn(3, "Amount", width=100)
            list_ctrl.InsertColumn(4, "Status", width=150)

            list_ctrl.Bind(wx.EVT_LIST_ITEM_ACTIVATED, self.on_transaction_activated)

            self.tx_list = list_ctrl
            return list_ctrl

        def refresh_transaction_list(self):
            """Refresh transaction list from wallet"""
            if self.f_refresh_list_ctrl_running:
                return
            
            # Don't refresh if system not initialized
            if not hasattr(self, 'system_initialized') or not self.system_initialized:
                return
                
            self.f_refresh_list_ctrl_running = True

            # Use CallAfter to avoid blocking GUI thread
            def refresh_async():
                try:
                    if not hasattr(self, 'tx_list') or not self.tx_list:
                        self.f_refresh_list_ctrl_running = False
                        return
                    
                    try:
                        self.tx_list.DeleteAllItems()
                    except Exception:
                        self.f_refresh_list_ctrl_running = False
                        return

                    # Check if wallet is available
                    try:
                        wallet = get_wallet()
                    except Exception:
                        self.f_refresh_list_ctrl_running = False
                        return
                        
                    if not wallet:
                        self.f_refresh_list_ctrl_running = False
                        return

                    # Get all transactions, sorted by time
                    transactions = []
                    for tx_hash, wtx in wallet.items():
                        if hasattr(wtx, "n_time_received") and wtx.n_time_received:
                            time_received = wtx.n_time_received
                        else:
                            time_received = int(time.time())
                        transactions.append((time_received, wtx))

                    transactions.sort(reverse=True)  # Newest first

                    for time_received, wtx in transactions:
                        try:
                            # Format date
                            try:
                                date_str = datetime.fromtimestamp(time_received).strftime(
                                    "%Y-%m-%d %H:%M"
                                )
                            except (ValueError, OSError):
                                date_str = "Unknown"

                            # Determine type
                            try:
                                if hasattr(wtx, 'is_coinbase') and wtx.is_coinbase():
                                    tx_type = "Mined"
                                elif hasattr(wtx, "f_from_me") and wtx.f_from_me:
                                    tx_type = "Sent"
                                else:
                                    tx_type = "Received"
                            except Exception:
                                tx_type = "Unknown"

                            # Get address
                            try:
                                address = self.get_transaction_address(wtx)
                            except Exception:
                                address = "Unknown"

                            # Format amount
                            try:
                                amount = format_money(wtx.get_value())
                            except Exception:
                                amount = "0.00"

                            # Status
                            try:
                                if hasattr(wtx, "f_spent") and wtx.f_spent:
                                    status = "Spent"
                                else:
                                    # Check confirmations
                                    try:
                                        chain = get_chain()
                                        if chain and hasattr(chain, 'best_index') and chain.best_index:
                                            confirmations = wtx.get_confirmations()
                                            if confirmations > 0:
                                                status = f"Confirmed ({confirmations})"
                                            else:
                                                status = "Unconfirmed"
                                        else:
                                            status = "Unconfirmed"
                                    except Exception:
                                        status = "Unknown"
                            except Exception:
                                status = "Unknown"

                            # Insert row - wrap in try/except to prevent crash on individual items
                            try:
                                index = self.tx_list.InsertItem(self.tx_list.GetItemCount(), date_str)
                                self.tx_list.SetItem(index, 1, tx_type)
                                self.tx_list.SetItem(index, 2, address)
                                self.tx_list.SetItem(index, 3, amount)
                                self.tx_list.SetItem(index, 4, status)
                                # Store transaction hash for details
                                try:
                                    self.tx_list.SetItemData(index, hash(str(wtx.txid)))
                                except Exception:
                                    pass  # Ignore if SetItemData fails
                            except Exception:
                                continue  # Skip this transaction if insertion fails
                        except Exception:
                            continue  # Skip this transaction if processing fails
                except Exception as e:
                    # Silently ignore errors to prevent crashes
                    pass
                finally:
                    self.f_refresh_list_ctrl_running = False
            
            # Defer the actual refresh to avoid blocking
            wx.CallAfter(refresh_async)

        def get_transaction_address(self, wtx):
            """Get address for transaction display"""
            try:
                # Try to extract address from outputs
                if wtx.vout:
                    for vout in wtx.vout:
                        if vout.script_pubkey and vout.script_pubkey.data:
                            # Extract pubkey hash from script
                            # This is simplified - full implementation would parse script
                            return "Address..."  # TODO: Parse script properly
                return "Unknown"
            except Exception:
                return "Unknown"

        def update_balance(self):
            """Update balance display"""
            try:
                if not hasattr(self, 'balance_text') or not self.balance_text:
                    return
                # Only try to get balance if chain is initialized
                try:
                    from cryptogenesis.chain import get_chain
                    chain = get_chain()
                    if chain and hasattr(chain, 'best_height') and chain.best_height >= 0:
                        balance = get_balance()
                        self.balance_text.SetLabel(format_money(balance) + " BTC")
                    else:
                        self.balance_text.SetLabel("0.00 BTC")
                except Exception:
                    self.balance_text.SetLabel("0.00 BTC")
            except Exception:
                pass  # Silently ignore errors

        def update_address(self):
            """Update address display"""
            try:
                if not hasattr(self, 'address_text') or not self.address_text:
                    return
                
                # Don't update if system not initialized
                if not hasattr(self, 'system_initialized') or not self.system_initialized:
                    self.address_text.SetValue("Not initialized")
                    return
                
                # Get address directly (should be fast)
                try:
                    address = get_wallet_address()
                    if address:
                        self.address_text.SetValue(address)
                    else:
                        # No address yet - generate one
                        try:
                            from cryptogenesis.wallet import generate_new_key
                            generate_new_key()
                            address = get_wallet_address()
                            if address:
                                self.address_text.SetValue(address)
                            else:
                                self.address_text.SetValue("No address available")
                        except Exception:
                            self.address_text.SetValue("Generating address...")
                except Exception as e:
                    self.address_text.SetValue(f"Error: {str(e)[:30]}")
            except Exception:
                pass  # Silently ignore errors

        def update_status(self):
            """Update status bar"""
            try:
                try:
                    chain = get_chain()
                    if chain and hasattr(chain, 'best_height') and chain.best_height >= 0:
                        height = chain.best_height
                        self.SetStatusText(f"Block height: {height}")
                    else:
                        self.SetStatusText("Not initialized")
                except Exception:
                    self.SetStatusText("Ready")
            except Exception:
                pass  # Silently ignore errors

        def refresh_all(self):
            """Refresh all UI elements"""
            # Don't refresh if system not initialized
            if not hasattr(self, 'system_initialized') or not self.system_initialized:
                return
                
            # Wrap in try-except to prevent crashes
            try:
                self.update_balance()
                self.update_address()
                self.refresh_transaction_list()
                self.update_status()
            except Exception:
                # Silently ignore errors to prevent crashes
                pass

        def on_timer(self, event):
            """Timer event - refresh UI"""
            # Timer is disabled to prevent crashes
            # Refresh only happens on user actions
            pass

        def on_send(self, event):
            """Open send dialog"""
            dialog = SendDialog(self)
            if dialog.ShowModal() == wx.ID_OK:
                self.refresh_all()
            dialog.Destroy()

        def on_address_book(self, event):
            """Open address book dialog"""
            dialog = AddressBookDialog(self)
            dialog.ShowModal()
            dialog.Destroy()

        def on_initialize_system(self, event):
            """Initialize Bitcoin system"""
            if hasattr(self, 'system_initialized') and self.system_initialized:
                wx.MessageBox("System is already initialized.", "Info", wx.OK | wx.ICON_INFORMATION)
                return
            
            # Show progress dialog
            progress = wx.ProgressDialog(
                "Initializing Bitcoin System",
                "Please wait while the Bitcoin system initializes...",
                maximum=100,
                parent=self,
                style=wx.PD_APP_MODAL | wx.PD_AUTO_HIDE
            )
            progress.Update(10, "Loading block index...")
            
            # Initialize in background thread
            import threading
            def init_thread():
                try:
                    from main import initialize_bitcoin_system
                    from types import SimpleNamespace
                    args = SimpleNamespace()
                    args.gui = True  # Skip network in GUI mode
                    args.generate = False
                    
                    # Update progress on main thread
                    wx.CallAfter(progress.Update, 30, "Loading wallet...")
                    import time
                    time.sleep(0.1)  # Small delay to let GUI update
                    
                    success = initialize_bitcoin_system(args)
                    
                    if success:
                        # All GUI updates must be on main thread
                        wx.CallAfter(progress.Update, 90, "Finalizing...")
                        import time
                        time.sleep(0.2)  # Brief delay
                        # Mark as initialized and start refresh timer
                        wx.CallAfter(self._on_initialization_complete)
                        wx.CallAfter(progress.Update, 100, "Initialization complete!")
                        # Close progress dialog after a brief delay
                        time.sleep(0.5)
                        wx.CallAfter(progress.Destroy)
                    else:
                        wx.CallAfter(progress.Destroy)
                        wx.CallAfter(lambda: wx.MessageBox(
                            "Initialization failed. Check console for details.",
                            "Error", wx.OK | wx.ICON_ERROR
                        ))
                except Exception as e:
                    wx.CallAfter(progress.Destroy)
                    wx.CallAfter(lambda: wx.MessageBox(
                        f"Error during initialization: {e}",
                        "Error", wx.OK | wx.ICON_ERROR
                    ))
            
            thread = threading.Thread(target=init_thread, daemon=True)
            thread.start()
        
        def _on_initialization_complete(self):
            """Called after initialization completes - must be on main thread"""
            try:
                self.system_initialized = True
                # Just update status - don't do any other updates that might crash
                try:
                    self.SetStatusText("System initialized - Use Options > Refresh to update")
                except Exception:
                    pass  # Silently ignore if status bar not available
                # NO automatic updates - user must manually refresh to prevent crashes
            except Exception as e:
                print(f"Error in _on_initialization_complete: {e}")
                import traceback
                traceback.print_exc()
        
        def on_refresh(self, event):
            """Manually refresh wallet and balance"""
            if not hasattr(self, 'system_initialized') or not self.system_initialized:
                wx.MessageBox("Please initialize the system first.", "Info", wx.OK | wx.ICON_INFORMATION)
                return
            
            # Refresh all UI elements
            try:
                self.refresh_all()
                self.SetStatusText("Refreshed")
            except Exception as e:
                wx.MessageBox(f"Error refreshing: {e}", "Error", wx.OK | wx.ICON_ERROR)
        
        def on_network(self, event):
            """Toggle network node"""
            if not hasattr(self, 'system_initialized') or not self.system_initialized:
                wx.MessageBox("Please initialize the system first.", "Info", wx.OK | wx.ICON_INFORMATION)
                return
            
            if self.network_running:
                # Stop network
                from cryptogenesis.network import stop_node
                stop_node()
                self.network_running = False
                self.menu_network.Check(False)
                self.SetStatusText("Network stopped")
            else:
                # Start network in background thread
                import threading
                def start_network_thread():
                    try:
                        from cryptogenesis.network import start_node
                        success, error_msg = start_node()
                        if success:
                            wx.CallAfter(lambda: self.SetStatusText("Network started"))
                            wx.CallAfter(lambda: setattr(self, 'network_running', True))
                            wx.CallAfter(lambda: self.menu_network.Check(True))
                        else:
                            wx.CallAfter(lambda: wx.MessageBox(
                                f"Failed to start network: {error_msg}",
                                "Error", wx.OK | wx.ICON_ERROR
                            ))
                    except Exception as e:
                        wx.CallAfter(lambda: wx.MessageBox(
                            f"Error starting network: {e}",
                            "Error", wx.OK | wx.ICON_ERROR
                        ))
                
                thread = threading.Thread(target=start_network_thread, daemon=True)
                thread.start()
                self.SetStatusText("Starting network...")
        
        def on_generate_coins(self, event):
            """Toggle mining"""
            if not hasattr(self, 'system_initialized') or not self.system_initialized:
                wx.MessageBox("Please initialize the system first.", "Info", wx.OK | wx.ICON_INFORMATION)
                return
                
            current = get_generate_bitcoins()
            new_state = not current
            set_generate_bitcoins(new_state)
            self.menu_generate.Check(new_state)

            if new_state:
                # Start mining thread
                start_mining()
            else:
                from cryptogenesis.mining import stop_mining

                stop_mining()

        def on_options(self, event):
            """Open options dialog"""
            dialog = OptionsDialog(self)
            dialog.ShowModal()
            dialog.Destroy()

        def on_about(self, event):
            """Show about dialog"""
            info = wx.adv.AboutDialogInfo()
            info.SetName("Bitcoin")
            info.SetVersion("0.1")
            info.SetDescription("Bitcoin v0.1 Python Implementation")
            info.SetCopyright("(c) 2009 Satoshi Nakamoto")
            wx.adv.AboutBox(info)

        def on_copy_address(self, event):
            """Copy address to clipboard"""
            if wx.TheClipboard.Open():
                wx.TheClipboard.SetData(wx.TextDataObject(self.address_text.GetValue()))
                wx.TheClipboard.Close()
                wx.MessageBox("Address copied to clipboard", "Info", wx.OK | wx.ICON_INFORMATION)

        def on_change_address(self, event):
            """Change address (generate new key)"""
            generate_new_key()
            self.update_address()
            wx.MessageBox("New address generated", "Info", wx.OK | wx.ICON_INFORMATION)

        def on_transaction_activated(self, event):
            """Show transaction details"""
            index = event.GetIndex()
            if index >= 0:
                # Get transaction from wallet
                wallet = get_wallet()
            if wallet:
                # Find transaction (simplified)
                dialog = wx.MessageDialog(
                    self,
                    "Transaction details not yet implemented",
                    "Transaction Details",
                    wx.OK,
                )
                dialog.ShowModal()
                dialog.Destroy()

        def on_exit(self, event):
            """Handle exit"""
            self.on_close(event)

        def on_close(self, event):
            """Handle window close"""
            try:
                from cryptogenesis.network import stop_node
                from cryptogenesis.mining import stop_mining

                stop_mining()
                if hasattr(self, 'network_running') and self.network_running:
                    stop_node()
                if hasattr(self, 'timer') and self.timer:
                    self.timer.Stop()
            except Exception:
                pass  # Silently ignore errors during shutdown
            self.Destroy()


    class SendDialog(wx.Dialog):
        """Send money dialog matching CSendDialog"""

        def __init__(self, parent, address=""):
            super().__init__(parent, title="Send Bitcoins", size=(450, 300))

            sizer = wx.BoxSizer(wx.VERTICAL)

            # Pay to address
            payto_label = wx.StaticText(self, label="Pay To:")
            sizer.Add(payto_label, 0, wx.ALL, 5)

            addr_sizer = wx.BoxSizer(wx.HORIZONTAL)
            self.address_ctrl = wx.TextCtrl(self, value=address, size=(300, -1))
            addr_sizer.Add(self.address_ctrl, 1, wx.EXPAND | wx.ALL, 5)

            addr_book_btn = wx.Button(self, label="Address Book")
            addr_book_btn.Bind(wx.EVT_BUTTON, self.on_address_book)
            addr_sizer.Add(addr_book_btn, 0, wx.ALL, 5)
            sizer.Add(addr_sizer, 0, wx.EXPAND)

            # Amount
            amount_label = wx.StaticText(self, label="Amount:")
            sizer.Add(amount_label, 0, wx.ALL, 5)

            self.amount_ctrl = wx.TextCtrl(self)
            sizer.Add(self.amount_ctrl, 0, wx.EXPAND | wx.ALL, 5)

            # Buttons
            btn_sizer = wx.BoxSizer(wx.HORIZONTAL)
            send_btn = wx.Button(self, wx.ID_OK, "Send")
            send_btn.Bind(wx.EVT_BUTTON, self.on_send)
            cancel_btn = wx.Button(self, wx.ID_CANCEL, "Cancel")
            btn_sizer.Add(send_btn, 0, wx.ALL, 5)
            btn_sizer.Add(cancel_btn, 0, wx.ALL, 5)
            sizer.Add(btn_sizer, 0, wx.ALIGN_CENTER)

            self.SetSizer(sizer)

        def on_send(self, event):
            """Send bitcoins"""
            address = self.address_ctrl.GetValue().strip()
            amount_str = self.amount_ctrl.GetValue().strip()

            if not address:
                wx.MessageBox("Please enter an address", "Error", wx.OK | wx.ICON_ERROR)
                return

            if not amount_str:
                wx.MessageBox("Please enter an amount", "Error", wx.OK | wx.ICON_ERROR)
                return

            try:
                amount = parse_money(amount_str)
                if amount <= 0:
                    wx.MessageBox("Amount must be greater than 0", "Error", wx.OK | wx.ICON_ERROR)
                    return

                # Send money
                if send_money(address, amount):
                    wx.MessageBox("Transaction sent successfully!", "Success", wx.OK | wx.ICON_INFORMATION)
                    self.EndModal(wx.ID_OK)
                else:
                    wx.MessageBox("Failed to send transaction", "Error", wx.OK | wx.ICON_ERROR)
            except ValueError as e:
                wx.MessageBox(f"Invalid amount: {e}", "Error", wx.OK | wx.ICON_ERROR)
            except Exception as e:
                wx.MessageBox(f"Error: {e}", "Error", wx.OK | wx.ICON_ERROR)

        def on_address_book(self, event):
            """Open address book"""
            dialog = AddressBookDialog(self)
            if dialog.ShowModal() == wx.ID_OK:
                selected = dialog.get_selected_address()
                if selected:
                    self.address_ctrl.SetValue(selected)
            dialog.Destroy()


    class AddressBookDialog(wx.Dialog):
        """Address book dialog matching CAddressBookDialog"""

        def __init__(self, parent):
            super().__init__(parent, title="Address Book", size=(600, 400))

            sizer = wx.BoxSizer(wx.VERTICAL)

            # List of addresses
            self.list_ctrl = wx.ListCtrl(self, style=wx.LC_REPORT | wx.LC_SINGLE_SEL)
            self.list_ctrl.InsertColumn(0, "Label", width=200)
            self.list_ctrl.InsertColumn(1, "Address", width=350)
            sizer.Add(self.list_ctrl, 1, wx.EXPAND | wx.ALL, 5)

            # Buttons
            btn_sizer = wx.BoxSizer(wx.HORIZONTAL)
            new_btn = wx.Button(self, label="New")
            new_btn.Bind(wx.EVT_BUTTON, self.on_new)
            edit_btn = wx.Button(self, label="Edit")
            edit_btn.Bind(wx.EVT_BUTTON, self.on_edit)
            delete_btn = wx.Button(self, label="Delete")
            delete_btn.Bind(wx.EVT_BUTTON, self.on_delete)
            btn_sizer.Add(new_btn, 0, wx.ALL, 5)
            btn_sizer.Add(edit_btn, 0, wx.ALL, 5)
            btn_sizer.Add(delete_btn, 0, wx.ALL, 5)
            sizer.Add(btn_sizer, 0, wx.ALIGN_CENTER)

            # OK/Cancel
            ok_btn = wx.Button(self, wx.ID_OK, "OK")
            cancel_btn = wx.Button(self, wx.ID_CANCEL, "Cancel")
            btn_sizer2 = wx.BoxSizer(wx.HORIZONTAL)
            btn_sizer2.Add(ok_btn, 0, wx.ALL, 5)
            btn_sizer2.Add(cancel_btn, 0, wx.ALL, 5)
            sizer.Add(btn_sizer2, 0, wx.ALIGN_CENTER)

            self.SetSizer(sizer)
            self.load_addresses()

        def load_addresses(self):
            """Load addresses from address book"""
            # TODO: Load from persistent storage
            # For now, show wallet addresses
            try:
                address = get_wallet_address()
                if address:
                    index = self.list_ctrl.InsertItem(self.list_ctrl.GetItemCount(), "My Address")
                    self.list_ctrl.SetItem(index, 1, address)
            except Exception:
                pass

        def get_selected_address(self):
            """Get selected address"""
            selection = self.list_ctrl.GetFirstSelected()
            if selection >= 0:
                return self.list_ctrl.GetItemText(selection, 1)
            return None

        def on_new(self, event):
            """Add new address"""
            # TODO: Implement
            wx.MessageBox("New address feature not yet implemented", "Info", wx.OK)

        def on_edit(self, event):
            """Edit address label"""
            # TODO: Implement
            wx.MessageBox("Edit address feature not yet implemented", "Info", wx.OK)

        def on_delete(self, event):
            """Delete address"""
            # TODO: Implement
            wx.MessageBox("Delete address feature not yet implemented", "Info", wx.OK)


    class OptionsDialog(wx.Dialog):
        """Options dialog matching COptionsDialog"""

        def __init__(self, parent):
            super().__init__(parent, title="Options", size=(400, 200))

            sizer = wx.BoxSizer(wx.VERTICAL)

            # Transaction fee
            fee_label = wx.StaticText(self, label="Transaction Fee:")
            sizer.Add(fee_label, 0, wx.ALL, 5)

            self.fee_ctrl = wx.TextCtrl(self)
            sizer.Add(self.fee_ctrl, 0, wx.EXPAND | wx.ALL, 5)

            # Buttons
            btn_sizer = wx.BoxSizer(wx.HORIZONTAL)
            ok_btn = wx.Button(self, wx.ID_OK, "OK")
            ok_btn.Bind(wx.EVT_BUTTON, self.on_ok)
            cancel_btn = wx.Button(self, wx.ID_CANCEL, "Cancel")
            btn_sizer.Add(ok_btn, 0, wx.ALL, 5)
            btn_sizer.Add(cancel_btn, 0, wx.ALL, 5)
            sizer.Add(btn_sizer, 0, wx.ALIGN_CENTER)

            self.SetSizer(sizer)
            self.load_settings()

        def load_settings(self):
            """Load current settings"""
            # TODO: Load from settings storage
            self.fee_ctrl.SetValue("0.01")

        def on_ok(self, event):
            """Save settings"""
            # TODO: Save to settings storage
            self.EndModal(wx.ID_OK)


    class BitcoinApp(wx.App):
        """Main application class matching CMyApp"""

        def __init__(self, init_func: Optional[Callable] = None, init_args=None):
            # Set attributes BEFORE calling super().__init__()
            # because OnInit() may be called during super().__init__()
            self.init_func = init_func
            if init_args is None:
                from types import SimpleNamespace
                self.init_args = SimpleNamespace()
            else:
                self.init_args = init_args
            super().__init__()

        def OnInit(self):
            """Initialize application - matches CMyApp::OnInit2()"""
            # Create and show main frame - NO initialization here
            try:
                self.frame = MainFrame(None)
                self.frame.Show()
                # Make sure the frame is raised to the front and focused
                self.frame.Raise()
                self.frame.SetFocus()
                self.frame.Center()  # Center the window on screen
            except Exception as e:
                print(f"ERROR: Failed to create MainFrame: {e}")
                import traceback
                traceback.print_exc()
                return False

            return True


if __name__ == "__main__":
    if wx is None:
            print("ERROR: wxPython not installed. Install with: pip install wxPython")
            sys.exit(1)

    app = BitcoinApp()
    app.MainLoop()

