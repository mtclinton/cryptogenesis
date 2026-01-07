"""
Mining View

View component for displaying mining status and controls.
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
    class MiningView:
        pass

else:

    class MiningView:
        """
        View component for mining display.
        Contains only UI elements, no business logic.
        """

        def __init__(self, parent):
            """
            Initialize mining view.

            Args:
                parent: Parent wx.Window
            """
            self.panel = wx.Panel(parent)
            self._create_ui()

        def _create_ui(self):
            """Create UI elements for mining view"""
            sizer = wx.BoxSizer(wx.HORIZONTAL)

            label = wx.StaticText(self.panel, label="Mining:")
            sizer.Add(label, 0, wx.ALL, 5)

            self.status_text = wx.StaticText(self.panel, label="Stopped")
            sizer.Add(self.status_text, 0, wx.ALL, 5)

            self.panel.SetSizer(sizer)

        def update_status(self, status: str):
            """
            Update mining status display.

            Args:
                status: Status string (e.g., "Running", "Stopped")
            """
            if self.status_text:
                self.status_text.SetLabel(f"Mining: {status}")

        def get_panel(self):
            """Get the main panel widget"""
            return self.panel

