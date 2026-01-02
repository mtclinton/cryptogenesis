"""
Wallet View

View component for displaying wallet information (balance, address).
Separated from controller logic.
"""

from typing import Optional

# Try to import wxPython
try:
    import wx
    WX_AVAILABLE = True
except ImportError:
    wx = None
    WX_AVAILABLE = False


if not WX_AVAILABLE:
    # Stub classes if wxPython is not available
    class WalletView:
        pass
else:

    class WalletView:
        """
        View component for wallet display.
        Contains only UI elements, no business logic.
        """

        def __init__(self, parent):
            """
            Initialize wallet view.
            
            Args:
                parent: Parent wx.Window
            """
            self.panel = wx.Panel(parent)
            self._create_ui()

        def _create_ui(self):
            """Create UI elements for wallet view"""
            sizer = wx.BoxSizer(wx.VERTICAL)

            # Balance panel
            balance_panel = self._create_balance_panel(self.panel)
            sizer.Add(balance_panel, 0, wx.EXPAND | wx.ALL, 5)

            # Address panel
            address_panel = self._create_address_panel(self.panel)
            sizer.Add(address_panel, 0, wx.EXPAND | wx.ALL, 5)

            self.panel.SetSizer(sizer)

        def _create_balance_panel(self, parent):
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

        def _create_address_panel(self, parent):
            """Create address display panel"""
            panel = wx.Panel(parent)
            sizer = wx.BoxSizer(wx.HORIZONTAL)

            label = wx.StaticText(panel, label="Your Address:")
            sizer.Add(label, 0, wx.ALL, 5)

            self.address_text = wx.TextCtrl(panel, style=wx.TE_READONLY)
            sizer.Add(self.address_text, 1, wx.EXPAND | wx.ALL, 5)

            self.copy_btn = wx.Button(panel, label="Copy")
            sizer.Add(self.copy_btn, 0, wx.ALL, 5)

            self.change_btn = wx.Button(panel, label="Change")
            sizer.Add(self.change_btn, 0, wx.ALL, 5)

            panel.SetSizer(sizer)
            return panel

        def update_balance(self, balance: str):
            """
            Update balance display.
            
            Args:
                balance: Balance string to display (e.g., "1.23 BTC")
            """
            if self.balance_text:
                self.balance_text.SetLabel(balance)

        def update_address(self, address: str):
            """
            Update address display.
            
            Args:
                address: Address string to display
            """
            if self.address_text:
                self.address_text.SetValue(address)

        def get_panel(self):
            """Get the main panel widget"""
            return self.panel


