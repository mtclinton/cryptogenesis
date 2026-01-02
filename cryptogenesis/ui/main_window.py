"""
Main Window

Main application window that composes view components.
Separated from controller logic. Contains only UI rendering logic.
All business logic and user actions are handled by GUIController.
"""

from typing import Callable, Optional, TYPE_CHECKING

# Try to import wxPython
try:
    import wx
    import wx.adv
    WX_AVAILABLE = True
except ImportError:
    wx = None
    wx.adv = None
    WX_AVAILABLE = False

from cryptogenesis.ui.mining_view import MiningView
from cryptogenesis.ui.transaction_view import TransactionView
from cryptogenesis.ui.wallet_view import WalletView

# Type checking only - avoid circular import
if TYPE_CHECKING:
    from cryptogenesis.ui.gui_controller import GUIController


if not WX_AVAILABLE:
    # Stub classes if wxPython is not available
    class MainWindow:
        pass
else:

    class MainWindow(wx.Frame):
        """
        Main application window.
        Composes view components but contains no business logic.
        Controller handles all business logic and event handling.
        
        This class is passive - it only renders UI and delegates all
        user actions to the controller. Views are updated by the controller,
        not directly by this class.
        """

        def __init__(self, parent, controller: Optional["GUIController"] = None):
            """
            Initialize main window.
            
            Args:
                parent: Parent wx.Window (usually None for top-level window)
                controller: Optional GUIController instance (can be set later)
            """
            super().__init__(parent, title="Bitcoin", size=(900, 700))
            
            # Controller reference (set by controller or passed in)
            self.controller: Optional["GUIController"] = controller
            
            # View components
            self.wallet_view: Optional[WalletView] = None
            self.transaction_view: Optional[TransactionView] = None
            self.mining_view: Optional[MiningView] = None
            
            # Menu items (for controller to access)
            self.menu_initialize = None
            self.menu_refresh = None
            self.menu_network = None
            self.menu_generate = None
            
            # Status flags (for UI state only, not business logic)
            self.system_initialized = False
            self.network_running = False
            
            # Create UI (pure rendering, no business logic)
            self._create_menu_bar()
            self._create_toolbar()
            self._create_main_panel()
            
            # Status bar
            self.CreateStatusBar()
            
            # Close event - delegate to controller if available
            self.Bind(wx.EVT_CLOSE, self._on_close)
        
        def set_controller(self, controller: "GUIController"):
            """
            Set the controller for this window.
            Called after window creation if controller wasn't passed in __init__.
            
            Args:
                controller: GUIController instance
            """
            self.controller = controller

        def _create_menu_bar(self):
            """
            Create menu bar.
            
            Pure UI rendering - no business logic.
            Menu items are created but handlers are bound by controller.
            """
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

        def _create_toolbar(self):
            """
            Create toolbar.
            
            Pure UI rendering - no business logic.
            Tool buttons are created but handlers are bound by controller.
            """
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
            
            # Store tool IDs for controller
            self.send_tool_id = send_tool.GetId()
            self.addr_tool_id = addr_tool.GetId()

        def _create_main_panel(self):
            """
            Create main panel with view components.
            
            Pure UI rendering - no business logic.
            Views are created but updated by controller.
            """
            panel = wx.Panel(self)
            sizer = wx.BoxSizer(wx.VERTICAL)

            # Wallet view (balance and address)
            self.wallet_view = WalletView(panel)
            sizer.Add(self.wallet_view.get_panel(), 0, wx.EXPAND | wx.ALL, 5)

            # Transaction view
            self.transaction_view = TransactionView(panel)
            sizer.Add(self.transaction_view.get_list_ctrl(), 1, wx.EXPAND | wx.ALL, 5)

            # Mining view (optional, can be added to status bar or separate panel)
            # For now, mining status will be in status bar

            panel.SetSizer(sizer)

        def _on_close(self, event):
            """
            Handle window close event.
            Delegates to controller if available, otherwise just closes.
            """
            if self.controller:
                # Let controller handle cleanup (stops mining, network, etc.)
                self.controller._on_close(event)
            else:
                # No controller - just close
                self.Destroy()

        def set_status_text(self, text: str):
            """
            Update status bar text.
            
            Args:
                text: Status text to display
            """
            if self.GetStatusBar():
                self.GetStatusBar().SetStatusText(text)

        def get_wallet_view(self) -> Optional[WalletView]:
            """Get wallet view component"""
            return self.wallet_view

        def get_transaction_view(self) -> Optional[TransactionView]:
            """Get transaction view component"""
            return self.transaction_view

        def get_mining_view(self) -> Optional[MiningView]:
            """Get mining view component"""
            return self.mining_view

        def bind_menu_event(self, menu_id, handler: Callable):
            """
            Bind menu event handler.
            Controller uses this to attach handlers.
            
            Args:
                menu_id: Menu item ID
                handler: Event handler function
            """
            self.Bind(wx.EVT_MENU, handler, id=menu_id)

        def bind_tool_event(self, tool_id, handler: Callable):
            """
            Bind toolbar event handler.
            Controller uses this to attach handlers.
            
            Args:
                tool_id: Tool item ID
                handler: Event handler function
            """
            self.Bind(wx.EVT_TOOL, handler, id=tool_id)


