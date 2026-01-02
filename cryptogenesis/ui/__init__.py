"""
UI Package

Contains GUI components separated into views and controllers.
"""

# Try to import wxPython
try:
    import wx
    WX_AVAILABLE = True
except ImportError:
    wx = None
    WX_AVAILABLE = False

if WX_AVAILABLE:
    from cryptogenesis.ui.gui_controller import GUIController
    from cryptogenesis.ui.main_window import MainWindow
    from cryptogenesis.ui.wallet_view import WalletView
    from cryptogenesis.ui.transaction_view import TransactionView
    from cryptogenesis.ui.mining_view import MiningView
    
    __all__ = [
        "GUIController",
        "MainWindow",
        "WalletView",
        "TransactionView",
        "MiningView",
        "WX_AVAILABLE",
    ]
else:
    # Stub classes if wxPython is not available
    class GUIController:
        pass
    class MainWindow:
        pass
    class WalletView:
        pass
    class TransactionView:
        pass
    class MiningView:
        pass
    
    __all__ = [
        "GUIController",
        "MainWindow",
        "WalletView",
        "TransactionView",
        "MiningView",
        "WX_AVAILABLE",
    ]

