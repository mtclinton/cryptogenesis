#!/usr/bin/env python3
"""
Copyright (c) 2009 Satoshi Nakamoto
Distributed under the MIT/X11 software license

Bitcoin v0.1 Python 3 Implementation -- headless entry point.

The desktop wxPython GUI has been removed: nodes run headless and the web
visualizer (visualization_server.py) is the interactive demo. This module is a
transitional headless entry and is superseded by cryptogenesis/node.py.
"""

import argparse
import signal
import sys
import threading
import time
from types import SimpleNamespace
from typing import Optional

from cryptogenesis.events import EventBus
from cryptogenesis.services import Services, get_services


def initialize_application(config: SimpleNamespace) -> Optional[Services]:
    """Build the service graph and start background services (headless)."""
    event_bus = EventBus()
    services = get_services(event_bus=event_bus)

    # Load persisted state (in-memory today) in the background.
    def initialize_state():
        try:
            result = services.blockchain_service.load_from_storage()
            if not result:
                print(f"Warning: Blockchain load failed: {result.error}")
            result = services.wallet_service.load_from_storage()
            if not result:
                print(f"Warning: Wallet load failed: {result.error}")
        except Exception as e:
            print(f"Error during state initialization: {e}")

    threading.Thread(target=initialize_state, daemon=True).start()

    if getattr(config, "start_network", False):

        def start_network_thread():
            try:
                if hasattr(services.network_service, "start"):
                    result = services.network_service.start()
                    print("Network started" if result else f"Network start failed: {result.error}")
                else:
                    print("Network service not yet implemented")
            except Exception as e:
                print(f"Error starting network: {e}")

        threading.Thread(target=start_network_thread, daemon=True).start()

    if getattr(config, "start_mining", False):

        def start_mining_thread():
            try:
                result = services.mining_service.start_mining()
                print("Mining started" if result else f"Mining start failed: {result.error}")
            except Exception as e:
                print(f"Error starting mining: {e}")

        threading.Thread(target=start_mining_thread, daemon=True).start()

    return services


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Bitcoin v0.1 Python 3 Implementation (headless)"
    )
    parser.add_argument("--network", action="store_true", help="Start network on startup")
    parser.add_argument("--mining", action="store_true", help="Start mining on startup")
    parser.add_argument("--test", action="store_true", help="Run basic functionality tests")
    args = parser.parse_args()

    if args.test:
        run_tests()
        return

    config = SimpleNamespace(start_network=args.network, start_mining=args.mining)
    services = initialize_application(config)
    if not services:
        print("Failed to initialize application")
        sys.exit(1)

    print("Application initialized (headless mode)")

    def signal_handler(signum, frame):
        print("\nShutting down...")
        services.mining_service.stop_mining()
        if hasattr(services.network_service, "stop"):
            services.network_service.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print("Press Ctrl+C to stop...")
    while True:
        time.sleep(1)


def run_tests():
    """Run basic functionality tests"""
    from cryptogenesis import COIN, Block, Key, Script, Transaction, TxIn, TxOut
    from cryptogenesis import block as block_module
    from cryptogenesis.transaction import OP_CHECKSIG

    print("Bitcoin v0.1 Python 3 Implementation")
    print("=" * 50)

    print("\nChecking genesis block...")
    print(f"Genesis block hash: {block_module.HASH_GENESIS_BLOCK.get_hex()}")

    print("\nTesting transaction creation...")
    key = Key()
    key.generate_new_key()
    pubkey = key.public_key
    print(f"Generated public key: {pubkey.hex()[:64]}...")

    tx = Transaction()
    tx.vin = [TxIn()]
    tx.vout = [TxOut(10 * COIN, Script())]
    tx.vout[0].script_pubkey.push_data(pubkey)
    tx.vout[0].script_pubkey.push_opcode(OP_CHECKSIG)
    print(f"Transaction hash: {tx.txid.get_hex()}")
    print(f"Transaction valid: {tx.check_transaction()}")

    print("\nTesting block creation...")
    block = Block()
    block.transactions = [tx]
    block.prev_block_hash = block_module.HASH_GENESIS_BLOCK
    block.merkle_root = block.build_merkle_tree()
    block.version = 1
    block.time = int(time.time())
    block.bits = 0x1D00FFFF
    block.nonce = 0
    print(f"Block hash: {block.get_hash().get_hex()}")
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
    tx_new.vin[0].script_sig.push_int(4, force_bignum=True)
    tx_new.vin[0].script_sig.push_data(timestamp)

    tx_new.vout = [TxOut()]
    tx_new.vout[0].value = 50 * COIN
    tx_new.vout[0].script_pubkey = Script()
    genesis_pubkey_hex = (
        "5F1DF16B2B704C8A578D0BBAF74D385CDE12C11EE50455F3C438EF4C3FBCF649B6DE"
        "611FEAE06279A60939E028A8D65C10B73071A6F16719274855FEB0FD8A6704"
    )
    genesis_pubkey_le = bytes(reversed(bytes.fromhex(genesis_pubkey_hex)))
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
