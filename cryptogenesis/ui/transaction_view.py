"""
Transaction View

View component for displaying transaction list.
Separated from controller logic.
"""

from typing import Callable, Optional

# Try to import wxPython
try:
    import wx
    WX_AVAILABLE = True
except ImportError:
    wx = None
    WX_AVAILABLE = False


if not WX_AVAILABLE:
    # Stub classes if wxPython is not available
    class TransactionView:
        pass
else:

    class TransactionView:
        """
        View component for transaction list display.
        Contains only UI elements, no business logic.
        """

        def __init__(self, parent):
            """
            Initialize transaction view.
            
            Args:
                parent: Parent wx.Window
            """
            self.list_ctrl = wx.ListCtrl(
                parent, style=wx.LC_REPORT | wx.LC_SINGLE_SEL
            )
            self._create_ui()

        def _create_ui(self):
            """Create UI elements for transaction view"""
            # Add columns matching Bitcoin v0.1
            self.list_ctrl.InsertColumn(0, "Date", width=120)
            self.list_ctrl.InsertColumn(1, "Type", width=80)
            self.list_ctrl.InsertColumn(2, "Address", width=200)
            self.list_ctrl.InsertColumn(3, "Amount", width=100)
            self.list_ctrl.InsertColumn(4, "Status", width=150)

        def set_on_activated(self, handler: Callable):
            """
            Set handler for transaction activation (double-click).
            
            Args:
                handler: Callable that takes event parameter
            """
            self.list_ctrl.Bind(wx.EVT_LIST_ITEM_ACTIVATED, handler)

        def clear(self):
            """Clear all items from the list"""
            if self.list_ctrl:
                self.list_ctrl.DeleteAllItems()

        def add_transaction(
            self,
            date: str,
            tx_type: str,
            address: str,
            amount: str,
            status: str
        ):
            """
            Add a transaction row to the list.
            
            Args:
                date: Date string
                tx_type: Transaction type (e.g., "Send", "Receive")
                address: Address string
                amount: Amount string (e.g., "1.23 BTC")
                status: Status string (e.g., "Confirmed")
            """
            if self.list_ctrl:
                index = self.list_ctrl.InsertItem(
                    self.list_ctrl.GetItemCount(), date
                )
                self.list_ctrl.SetItem(index, 1, tx_type)
                self.list_ctrl.SetItem(index, 2, address)
                self.list_ctrl.SetItem(index, 3, amount)
                self.list_ctrl.SetItem(index, 4, status)

        def get_list_ctrl(self):
            """Get the list control widget"""
            return self.list_ctrl

