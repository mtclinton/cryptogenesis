#!/usr/bin/env python3
"""
Copyright (c) 2009 Satoshi Nakamoto
Distributed under the MIT/X11 software license

Bitcoin v0.1 Python 3 Implementation
Main entry point
"""

import argparse
import sys
import threading
from types import SimpleNamespace
from typing import Optional

# Try to import wxPython for GUI
try:
    import wx

    # Suppress wxPython debug messages
    wx.Log.SetLogLevel(wx.LOG_Error)
    WX_AVAILABLE = True
except ImportError:
    wx = None
    WX_AVAILABLE = False

from cryptogenesis.events import EventBus
from cryptogenesis.services import Services, get_services
from cryptogenesis.ui import GUIController, MainWindow

# Global variable to hold services for threading
_global_services = None


def initialize_application(config: SimpleNamespace) -> Optional[Services]:
    """
    Initialize application following proper sequence.

    Sequence:
    1. Create event_bus
    2. Create state instances
    3. Create services with dependencies
    4. Initialize state (load from storage)
    5. Start background services (network, mining) if enabled
    6. Create GUI if gui_mode
    7. Create GUIController with services and event_bus
    8. Show window and start event loop

    Args:
        config: Configuration object with:
            - gui_mode: bool - Whether to show GUI
            - start_network: bool - Whether to start network on startup
            - start_mining: bool - Whether to start mining on startup
            - private_network: bool - Whether to use private network parameters

    Returns:
        Services instance if successful, None if GUI mode (event loop runs)
    """
    # Step 1: Set network mode if private network is enabled
    if getattr(config, "private_network", False):
        from cryptogenesis.block import initialize_private_network, set_genesis_mode
        from cryptogenesis.network_core import set_network_mode

        set_network_mode("private")
        set_genesis_mode("private")

    # Step 2: Create event_bus
    event_bus = EventBus()

    # Step 3 & 4: Create state instances and services with dependencies
    # get_services() handles both state creation and service creation
    services = get_services(event_bus=event_bus)
    global _global_services
    _global_services = services

    # Initialize private network genesis block after services are created
    if getattr(config, "private_network", False):
        try:
            initialize_private_network(services.blockchain_service)
        except Exception as e:
            print(f"Warning: Could not initialize private network: {e}")

    # Step 6: Initialize state (load from storage)
    # Run in background thread to avoid blocking
    def initialize_state():
        """Initialize state from storage in background"""
        try:
            # Access global services
            global _global_services
            services_arg = _global_services

            # Load blockchain from storage
            result = services_arg.blockchain_service.load_from_storage()
            if not result:
                print(f"Warning: Blockchain load failed: {result.error}")

            # Load wallet from storage
            result = services_arg.wallet_service.load_from_storage()
            if not result:
                print(f"Warning: Wallet load failed: {result.error}")
        except Exception as e:
            print(f"Error during state initialization: {e}")
            import traceback

            traceback.print_exc()

    # Start initialization in background thread
    init_thread = threading.Thread(target=initialize_state, daemon=True)
    init_thread.start()

    # For private network, wait for initialization to complete
    # since we need the genesis block to be loaded before GUI starts
    if getattr(config, "private_network", False):
        init_thread.join(timeout=5.0)  # Wait up to 5 seconds for initialization

    # Step 7: Start background services if enabled
    if getattr(config, "start_network", False):

        def start_network_thread():
            """Start network in background"""
            try:
                if hasattr(services.network_service, "start"):
                    result = services.network_service.start()
                    if result:
                        print("Network started")
                    else:
                        print(f"Network start failed: {result.error}")
                else:
                    print("Network service not yet implemented")
            except Exception as e:
                print(f"Error starting network: {e}")

        threading.Thread(target=start_network_thread, daemon=True).start()

    if getattr(config, "start_mining", False):

        def start_mining_thread():
            """Start mining in background"""
            try:
                result = services.mining_service.start_mining()
                if result:
                    print("Mining started")
                else:
                    print(f"Mining start failed: {result.error}")
            except Exception as e:
                print(f"Error starting mining: {e}")

        threading.Thread(target=start_mining_thread, daemon=True).start()

    # Step 8: Create GUI if gui_mode
    if getattr(config, "gui_mode", False):
        if not UI_AVAILABLE:
            print("ERROR: GUI requested but wxPython not available")
            print("Install with: pip install wxPython")
            return None

        # Create wx.App
        app = wx.App(False)  # False = don't redirect stdout/stderr

        # Step 9: Create GUI components
        # Create MainWindow first (appears immediately)
        main_window = MainWindow(None)

        # Create GUIController with services and event_bus
        controller = GUIController(main_window=main_window, services=services, event_bus=event_bus)

        # Set controller reference in window
        main_window.set_controller(controller)

        # Step 10: Show window and start event loop
        main_window.Show()
        main_window.Raise()
        main_window.SetFocus()
        main_window.Center()

        # Start event loop (blocks until window is closed)
        # GUI updates happen via event subscriptions, not timers
        app.MainLoop()

        # Cleanup after event loop exits
        services.mining_service.stop_mining()
        if hasattr(services.network_service, "stop"):
            services.network_service.stop()

        return None  # GUI mode doesn't return services
    else:
        # Non-GUI mode: return services for programmatic use
        return services


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Bitcoin v0.1 Python 3 Implementation")
    parser.add_argument("--gui", action="store_true", help="Start GUI mode")
    parser.add_argument("--network", action="store_true", help="Start network on startup")
    parser.add_argument("--mining", action="store_true", help="Start mining on startup")
    parser.add_argument("--test", action="store_true", help="Run basic functionality tests")
    parser.add_argument(
        "--private-network",
        action="store_true",
        help="Run with private network parameters (isolated blockchain)",
    )

    args = parser.parse_args()

    # Create config object
    config = SimpleNamespace(
        gui_mode=args.gui,
        start_network=args.network,
        start_mining=args.mining,
        private_network=args.private_network,
    )

    # Run tests if requested
    if args.test:
        # Set network mode for testing if private network is requested
        if args.private_network:
            from cryptogenesis.block import initialize_private_network, set_genesis_mode
            from cryptogenesis.network_core import set_network_mode

            set_network_mode("private")
            set_genesis_mode("private")
            # For tests, initialize without blockchain_service since services aren't created
            initialize_private_network()
        run_tests()
        return

    # Initialize application
    if config.gui_mode:
        # GUI mode: initialize and run event loop
        services = initialize_application(config)
        if services is None:
            # Event loop completed, application exiting
            sys.exit(0)
    else:
        # Non-GUI mode: initialize and keep process alive
        services = initialize_application(config)
        if services:
            print("Application initialized (non-GUI mode)")
            print("Services available for programmatic use")

            # Keep process alive if mining or network services are running
            try:
                import signal
                import time

                def signal_handler(signum, frame):
                    """Handle shutdown signals"""
                    print("\nShutting down...")
                    if hasattr(services, "mining_service"):
                        services.mining_service.stop_mining()
                    if hasattr(services, "network_service") and hasattr(
                        services.network_service, "stop"
                    ):
                        services.network_service.stop()
                    sys.exit(0)

                # Register signal handlers
                signal.signal(signal.SIGINT, signal_handler)
                signal.signal(signal.SIGTERM, signal_handler)

                print("Press Ctrl+C to stop...")

                # Keep process alive
                while True:
                    time.sleep(1)

                    # Check if mining is still active
                    if (
                        hasattr(services, "mining_service")
                        and not services.mining_service.is_mining()
                    ):
                        print("Mining stopped, exiting...")
                        break

            except KeyboardInterrupt:
                print("\nInterrupted by user")
                if hasattr(services, "mining_service"):
                    services.mining_service.stop_mining()
                if hasattr(services, "network_service") and hasattr(
                    services.network_service, "stop"
                ):
                    services.network_service.stop()
                sys.exit(0)
        else:
            print("Failed to initialize application")
            sys.exit(1)


def run_tests():
    """Run basic functionality tests"""
    import time

    from cryptogenesis import COIN, Block, Key, Script, Transaction, TxIn, TxOut
    from cryptogenesis import block as block_module
    from cryptogenesis import uint256

    print("Bitcoin v0.1 Python 3 Implementation")
    print("=" * 50)

    # Check genesis block
    print("\nChecking genesis block...")
    print(f"Current genesis block hash: {block_module.HASH_GENESIS_BLOCK.get_hex()}")

    # For private network, we expect a different hash
    from cryptogenesis.network_core import get_network_mode

    network_mode = get_network_mode()
    print(f"Network mode: {network_mode}")

    if network_mode == "private":
        print("✓ Private network mode active!")
        # The genesis hash should be different from mainnet
        mainnet_hash = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        if block_module.HASH_GENESIS_BLOCK.get_hex() != mainnet_hash:
            print("✓ Private network genesis block hash is different from mainnet!")
        else:
            print("⚠ Private network genesis block hash matches mainnet (unexpected)")
    else:
        print("Using mainnet parameters")

    # Skip detailed genesis block info for now (chain not fully initialized in test mode)

    # Test transaction creation
    print("\n\nTesting transaction creation...")
    key = Key()
    key.generate_new_key()
    pubkey = key.public_key
    print(f"Generated public key: {pubkey.hex()[:64]}...")

    # Create a simple transaction
    tx = Transaction()
    tx.vin = [TxIn()]
    tx.vout = [TxOut(10 * COIN, Script())]
    tx.vout[0].script_pubkey.push_data(pubkey)
    from cryptogenesis.transaction import OP_CHECKSIG

    tx.vout[0].script_pubkey.push_opcode(OP_CHECKSIG)

    tx_hash = tx.txid
    print(f"Transaction hash: {tx_hash.get_hex()}")
    print(f"Transaction valid: {tx.check_transaction()}")

    # Test block creation
    print("\n\nTesting block creation...")
    block = Block()
    block.transactions = [tx]
    block.prev_block_hash = block_module.HASH_GENESIS_BLOCK
    block.merkle_root = block.build_merkle_tree()
    block.version = 1
    block.time = int(time.time())
    block.bits = 0x1D00FFFF
    block.nonce = 0

    block_hash = block.get_hash()
    print(f"Block hash: {block_hash.get_hex()}")
    print(f"Block valid: {block.check_block()}")

    print("\n" + "=" * 50)
    print("Basic functionality test complete!")


def create_genesis_block():
    """Create the genesis block"""
    from cryptogenesis import COIN, Block, Script, Transaction, TxIn, TxOut, uint256
    from cryptogenesis.transaction import OP_CHECKSIG

    # Genesis block timestamp
    timestamp = b"The Times 03/Jan/2009 Chancellor on brink of " b"second bailout for banks"

    tx_new = Transaction()
    tx_new.vin = [TxIn()]
    tx_new.vin[0].prevout.set_null()
    tx_new.vin[0].script_sig = Script()
    tx_new.vin[0].script_sig.push_int(486604799, force_bignum=True)
    tx_new.vin[0].script_sig.push_int(4, force_bignum=True)  # BigNum(4) in original
    tx_new.vin[0].script_sig.push_data(timestamp)

    tx_new.vout = [TxOut()]
    tx_new.vout[0].value = 50 * COIN
    tx_new.vout[0].script_pubkey = Script()
    # Genesis block pubkey - BigNum('0x...') parses as big-endian,
    # then getvch() reverses to little-endian
    genesis_pubkey_hex = (
        "5F1DF16B2B704C8A578D0BBAF74D385CDE12C11EE50455F3C438EF4C3FBCF649B6DE"
        "611FEAE06279A60939E028A8D65C10B73071A6F16719274855FEB0FD8A6704"
    )
    genesis_pubkey_be = bytes.fromhex(genesis_pubkey_hex)  # Big-endian
    genesis_pubkey_le = bytes(
        reversed(genesis_pubkey_be)
    )  # Little-endian (after BigNum.getvch() reverse)
    tx_new.vout[0].script_pubkey.push_data(genesis_pubkey_le)
    tx_new.vout[0].script_pubkey.push_opcode(OP_CHECKSIG)

    block = Block()
    block.transactions = [tx_new]
    block.prev_block_hash = uint256(0)
    block.merkle_root = block.build_merkle_tree()
    block.version = 1
    block.time = 1231006505  # Genesis block time
    block.bits = 0x1D00FFFF
    block.nonce = 2083236893

    return block


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n\nError: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
