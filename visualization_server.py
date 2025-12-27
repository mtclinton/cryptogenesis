#!/usr/bin/env python3
"""
Blockchain Visualization Server
Serves a Three.js visualization of the blockchain and nodes
"""

import json
import os
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

# Import blockchain components
from cryptogenesis.chain import get_chain


class VisualizationHandler(BaseHTTPRequestHandler):
    """HTTP handler for visualization server"""

    def do_GET(self):
        """Handle GET requests"""
        if self.path == "/" or self.path == "/index.html":
            self.serve_html()
        elif self.path == "/visualization.js":
            self.serve_js()
        elif self.path == "/api/blockchain":
            self.serve_blockchain_data()
        elif self.path == "/api/nodes":
            self.serve_nodes_data()
        elif self.path == "/api/wallets":
            self.serve_wallets_data()
        elif self.path.startswith("/api/block/"):
            block_hash = self.path.split("/")[-1]
            self.serve_block_data(block_hash)
        else:
            self.send_error(404)

    def serve_html(self):
        """Serve the HTML visualization page"""
        html_content = get_visualization_html()
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(html_content.encode())

    def get_blockchain_from_node1(self):
        """Get blockchain data from node1's API"""
        try:
            import socket
            import urllib.request

            # Try to connect to node1's API
            try:
                ip = socket.gethostbyname("node1")
                url = f"http://{ip}:8081/api/blockchain"
                with urllib.request.urlopen(url, timeout=2) as response:
                    data = json.loads(response.read().decode())
                    return data
            except Exception as e:
                print(f"Could not fetch from node1: {e}")
                return None
        except Exception:
            return None

    def serve_blockchain_data(self):
        """Serve blockchain data as JSON"""
        try:
            # Try to get data from node1 first (most up-to-date)
            node1_data = self.get_blockchain_from_node1()
            if node1_data:
                print(
                    f"API: Using node1 data: {len(node1_data['blocks'])} blocks, "
                    f"height={node1_data['height']}"
                )
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps(node1_data).encode())
                return

            # Fallback to local chain
            chain = get_chain()
            best_index = chain.get_best_index()

            # Helper function to extract wallet address from script
            def extract_wallet_from_script(script):
                """Extract wallet address (pubkey hash) from script"""
                import struct

                from cryptogenesis.crypto import hash160
                from cryptogenesis.transaction import OP_PUSHDATA1, OP_PUSHDATA2

                if not script or not script.data:
                    return None

                # Script format: [length] [pubkey bytes] [OP_CHECKSIG]
                # Parse script bytearray to find pubkey
                data = script.data
                i = 0
                while i < len(data):
                    opcode = data[i]

                    # Check if this is a push data opcode
                    if opcode < OP_PUSHDATA1:
                        # Direct push: opcode is the length
                        length = opcode
                        if length == 65 and i + 1 + length <= len(data):
                            # Found 65-byte data - likely pubkey
                            pubkey = bytes(data[i + 1 : i + 1 + length])
                            if len(pubkey) == 65:
                                return hash160(pubkey).hex()
                        i += 1 + length
                    elif opcode == OP_PUSHDATA1:
                        # OP_PUSHDATA1: next byte is length
                        if i + 1 < len(data):
                            length = data[i + 1]
                            if length == 65 and i + 2 + length <= len(data):
                                pubkey = bytes(data[i + 2 : i + 2 + length])
                                if len(pubkey) == 65:
                                    return hash160(pubkey).hex()
                            i += 2 + length
                        else:
                            break
                    elif opcode == OP_PUSHDATA2:
                        # OP_PUSHDATA2: next 2 bytes (little-endian) are length
                        if i + 2 < len(data):
                            length = struct.unpack("<H", bytes(data[i + 1 : i + 3]))[0]
                            if length == 65 and i + 3 + length <= len(data):
                                pubkey = bytes(data[i + 3 : i + 3 + length])
                                if len(pubkey) == 65:
                                    return hash160(pubkey).hex()
                            i += 3 + length
                        else:
                            break
                    else:
                        # Other opcode, skip
                        i += 1

                return None

            # Helper function to identify node from wallet address
            def identify_node_from_address(wallet_addr):
                """Identify which node owns this wallet address"""
                import hashlib

                from cryptogenesis.crypto import Key, hash160

                for node_i in range(1, 11):
                    try:
                        seed = hashlib.sha256(f"node_{node_i}_wallet_seed".encode()).digest()
                        test_key = Key()
                        test_key.set_privkey(seed[:32])
                        test_pubkey = test_key.get_pubkey()
                        test_addr = hash160(test_pubkey).hex()
                        if test_addr == wallet_addr:
                            return f"node{node_i}"
                    except Exception:
                        continue
                return None

            # Get blockchain data
            blocks = []
            current = best_index
            height = 0
            while current and height < 100:  # Limit to last 100 blocks
                try:
                    # Load block from storage
                    block = chain.get_block(current.block_hash)
                    if not block:
                        print(f"API: Could not load block at height {height}")
                        break

                    # Include transaction details with wallet addresses
                    tx_details = []
                    if hasattr(block, "transactions") and block.transactions:
                        for tx_idx, tx in enumerate(block.transactions):
                            tx_info = {
                                "index": tx_idx,
                                "hash": tx.get_hash().get_hex()[:16],
                                "is_coinbase": tx.is_coinbase(),
                            }

                            # For coinbase: show destination wallet
                            if tx.is_coinbase() and tx.vout:
                                for vout in tx.vout:
                                    wallet_addr = extract_wallet_from_script(vout.script_pubkey)
                                    if wallet_addr:
                                        # Identify node BEFORE truncating address
                                        node_id = identify_node_from_address(wallet_addr)
                                        # Store full address for matching, but show truncated
                                        tx_info["to_wallet"] = wallet_addr[:16] + "..."
                                        tx_info["to_wallet_full"] = wallet_addr
                                        if node_id:
                                            tx_info["to_node"] = node_id
                                        break
                            else:
                                # For regular transactions: show to wallets
                                to_wallets = []
                                for vout in tx.vout:
                                    wallet_addr = extract_wallet_from_script(vout.script_pubkey)
                                    if wallet_addr:
                                        node_id = identify_node_from_address(wallet_addr)
                                        wallet_display = wallet_addr[:16] + "..."
                                        if node_id:
                                            wallet_display += f" ({node_id})"
                                        to_wallets.append(wallet_display)

                                if to_wallets:
                                    tx_info["to_wallets"] = to_wallets

                            tx_details.append(tx_info)

                    block_data = {
                        "hash": current.block_hash.get_hex(),
                        "height": current.height,
                        "prev_hash": (current.prev.block_hash.get_hex() if current.prev else None),
                        "time": block.time if hasattr(block, "time") else 0,
                        "transactions": (
                            len(block.transactions) if hasattr(block, "transactions") else 0
                        ),
                        "transaction_details": tx_details,
                    }
                    blocks.append(block_data)
                    current = current.prev
                    height += 1
                except Exception as e:
                    print(f"API: Error processing block at height {height}: {e}")
                    import traceback

                    traceback.print_exc()
                    break

            data = {
                "height": (
                    chain.best_height
                    if hasattr(chain, "best_height")
                    else (best_index.height if best_index else 0)
                ),
                "blocks": blocks,
                "timestamp": time.time(),
            }

            print(f"API: Returning {len(blocks)} blocks, height={data['height']}")

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode())
        except Exception as e:
            print(f"API: Error in serve_blockchain_data: {e}")
            import traceback

            traceback.print_exc()
            self.send_error(500, str(e))

    def serve_nodes_data(self):
        """Serve nodes data as JSON"""
        try:
            # Get node count from environment or use default
            node_count = int(os.environ.get("NODE_COUNT", "10"))

            # Create node list (simplified - in real implementation, get from network)
            node_list = []
            for i in range(1, node_count + 1):
                node_data = {
                    "id": f"node{i}",
                    "addr": f"192.168.200.{10 + i}:8333",
                    "connected": True,  # Simplified
                }
                node_list.append(node_data)

            data = {
                "nodes": node_list,
                "count": len(node_list),
                "timestamp": time.time(),
            }

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode())
        except Exception as e:
            self.send_error(500, str(e))

    def serve_wallets_data(self):
        """Serve wallets data as JSON by querying each node's API"""
        try:
            import socket
            import urllib.request

            wallets = []
            node_count = int(os.environ.get("NODE_COUNT", "10"))

            # Query each node's wallet API
            # Use container names (node1, node2, etc.) which work in Docker network
            for i in range(1, node_count + 1):
                node_id = f"node{i}"
                # Use container name for Docker network access
                wallet_url = f"http://{node_id}:8081/api/wallet"

                try:
                    # Try to fetch wallet data from node
                    req = urllib.request.Request(wallet_url)
                    req.add_header("User-Agent", "VisualizationServer/1.0")
                    with urllib.request.urlopen(req, timeout=2) as response:
                        if response.status == 200:
                            wallet_data = json.loads(response.read().decode())
                            wallets.append(wallet_data)
                        else:
                            # Node not responding, add placeholder
                            wallets.append(
                                {
                                    "node_id": node_id,
                                    "wallet_address": None,
                                    "balance": 0,
                                    "transaction_count": 0,
                                }
                            )
                except (urllib.error.URLError, socket.timeout, socket.gaierror):
                    # Node not available, add placeholder
                    wallets.append(
                        {
                            "node_id": node_id,
                            "wallet_address": None,
                            "balance": 0,
                            "transaction_count": 0,
                        }
                    )
                except Exception as e:
                    print(f"API: Error querying {node_id}: {e}")
                    wallets.append(
                        {
                            "node_id": node_id,
                            "wallet_address": None,
                            "balance": 0,
                            "transaction_count": 0,
                        }
                    )

            data = {
                "wallets": wallets,
                "timestamp": time.time(),
            }

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode())
        except Exception as e:
            print(f"API: Error in serve_wallets_data: {e}")
            import traceback

            traceback.print_exc()
            self.send_error(500, str(e))

    def serve_block_data(self, block_hash: str):
        """Serve specific block data"""
        try:
            # Find block by hash
            # This is simplified - you'd need to implement block lookup
            data = {"hash": block_hash, "found": False}

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode())
        except Exception as e:
            self.send_error(500, str(e))

    def log_message(self, format, *args):
        """Suppress default logging"""
        pass


def get_visualization_js() -> str:
    """Get the JavaScript content for visualization"""
    js_path = os.path.join(os.path.dirname(__file__), "static", "visualization.js")
    try:
        with open(js_path, "r") as f:
            return f.read()
    except Exception:
        return "console.error('Could not load visualization.js');"


def get_visualization_html() -> str:
    """Get the HTML content for visualization"""
    js_content = get_visualization_js()
    return (
        """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bitcoin Blockchain Visualization</title>
    <style>
        body {
            margin: 0;
            padding: 0;
            overflow: hidden;
            font-family: Arial, sans-serif;
            background: #000;
            color: #fff;
        }
        #info {
            position: absolute;
            top: 10px;
            left: 10px;
            background: rgba(0, 0, 0, 0.7);
            padding: 15px;
            border-radius: 5px;
            z-index: 100;
        }
        #info h2 {
            margin: 0 0 10px 0;
            color: #f0a000;
        }
        #info div {
            margin: 5px 0;
        }
        .stat {
            color: #0f0;
        }
        #sidebar {
            position: absolute;
            left: 0;
            top: 0;
            width: 300px;
            height: 100vh;
            background: rgba(20, 20, 20, 0.95);
            border-right: 2px solid #333;
            overflow-y: auto;
            z-index: 200;
            padding: 10px;
            box-sizing: border-box;
        }
        #sidebar h3 {
            margin: 0 0 15px 0;
            color: #f0a000;
            font-size: 18px;
        }
        .block-item {
            background: rgba(40, 40, 40, 0.8);
            border: 1px solid #555;
            border-radius: 5px;
            padding: 10px;
            margin-bottom: 10px;
            cursor: pointer;
            transition: all 0.2s;
        }
        .block-item:hover {
            background: rgba(60, 60, 60, 0.9);
            border-color: #f0a000;
        }
        .block-item.selected {
            background: rgba(80, 60, 0, 0.9);
            border-color: #f0a000;
        }
        .block-item .block-height {
            font-weight: bold;
            color: #0f0;
            font-size: 16px;
        }
        .block-item .block-hash {
            font-size: 11px;
            color: #aaa;
            word-break: break-all;
            margin-top: 5px;
        }
        .block-item .block-time {
            font-size: 12px;
            color: #888;
            margin-top: 5px;
        }
        .block-item .block-txs {
            font-size: 12px;
            color: #0ff;
            margin-top: 5px;
        }
        .wallet-item {
            background: rgba(40, 40, 40, 0.8);
            border: 1px solid #555;
            border-radius: 5px;
            padding: 10px;
            margin-bottom: 10px;
        }
        .wallet-item .wallet-node {
            font-weight: bold;
            color: #f0a000;
            font-size: 14px;
            margin-bottom: 5px;
        }
        .wallet-item .wallet-balance {
            font-size: 16px;
            font-weight: bold;
        }
        .wallet-item .wallet-tx-count {
            font-size: 12px;
            color: #0ff;
            margin-top: 5px;
        }
        #block-details {
            position: absolute;
            right: 0;
            top: 0;
            width: 350px;
            height: 100vh;
            background: rgba(20, 20, 20, 0.95);
            border-left: 2px solid #333;
            overflow-y: auto;
            z-index: 200;
            padding: 15px;
            box-sizing: border-box;
            display: none;
        }
        #block-details.visible {
            display: block;
        }
        #block-details h3 {
            margin: 0 0 15px 0;
            color: #f0a000;
            font-size: 18px;
        }
        .detail-item {
            margin-bottom: 15px;
            padding: 10px;
            background: rgba(40, 40, 40, 0.8);
            border-radius: 5px;
        }
        .detail-item label {
            display: block;
            color: #aaa;
            font-size: 12px;
            margin-bottom: 5px;
        }
        .detail-item .value {
            color: #fff;
            font-size: 14px;
            word-break: break-all;
        }
        .transaction-item {
            background: rgba(30, 30, 30, 0.8);
            border: 1px solid #444;
            border-radius: 5px;
            padding: 10px;
            margin-bottom: 10px;
        }
        .transaction-item .tx-hash {
            font-size: 11px;
            color: #0ff;
            word-break: break-all;
            margin-bottom: 5px;
        }
        .transaction-item .tx-info {
            font-size: 12px;
            color: #aaa;
        }
        #close-details {
            position: absolute;
            top: 10px;
            right: 10px;
            background: #f00;
            color: #fff;
            border: none;
            border-radius: 3px;
            padding: 5px 10px;
            cursor: pointer;
            font-size: 14px;
        }
        #close-details:hover {
            background: #c00;
        }
    </style>
</head>
<body>
    <div id="sidebar">
        <h3>Blocks</h3>
        <div id="blockList"></div>
        <h3 style="margin-top: 30px;">Wallets</h3>
        <div id="walletSection"></div>
    </div>

    <div id="info">
        <h2>Bitcoin Network Visualization</h2>
        <div>Height: <span class="stat" id="height">0</span></div>
        <div>Blocks: <span class="stat" id="blockCount">0</span></div>
        <div>Last Update: <span class="stat" id="lastUpdate">-</span></div>
    </div>

    <div id="block-details">
        <button id="close-details">×</button>
        <h3>Block Details</h3>
        <div id="detailsContent"></div>
    </div>

    <script type="importmap">
    {
        "imports": {
            "three": "https://cdn.jsdelivr.net/npm/three@0.160.0/build/three.module.js",
            "three/addons/": "https://cdn.jsdelivr.net/npm/three@0.160.0/examples/jsm/"
        }
    }
    </script>
    <script type="module">
        // Inline the JS to avoid CORS issues
        """
        + js_content
        + """
    </script>
</body>
</html>"""
    )


def initialize_blockchain():
    """Initialize blockchain with genesis block"""
    from cryptogenesis.block import HASH_GENESIS_BLOCK
    from cryptogenesis.chain import get_chain

    chain = get_chain()

    # Check if genesis block already exists
    if chain.has_block(HASH_GENESIS_BLOCK):
        print("Blockchain already initialized with genesis block")
        return

    # Create and accept genesis block
    print("Initializing blockchain with genesis block...")

    # Import and use the same genesis block creation as run_node.py
    import importlib.util

    run_node_path = os.path.join(os.path.dirname(__file__), "run_node.py")
    spec = importlib.util.spec_from_file_location("run_node", run_node_path)
    run_node_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(run_node_module)

    genesis_block = run_node_module.create_genesis_block()

    # Use accept_block for genesis (same as run_node.py)
    if chain.accept_block(genesis_block):
        print(f"Genesis block accepted. Height: {chain.best_height}")
    else:
        print("Failed to accept genesis block")


def start_network_node():
    """Start network node to receive blocks from peers"""
    import socket
    import threading
    import time

    from cryptogenesis.network import Address, connect_node, start_node

    print("\nStarting network node for visualization server...")
    success, error = start_node()
    if not success:
        print(f"WARNING: Failed to start network node: {error}")
        return

    print("Network node started")

    # Connect to a few peers to receive blocks
    # Connect to node1 (which should be running)
    def connect_to_peers():
        try:
            time.sleep(3)  # Wait for network to be ready
            ip = socket.gethostbyname("node1")
            ip_int = int.from_bytes(socket.inet_aton(ip), byteorder="big")
            port_net = socket.htons(8333)
            addr = Address(ip_int, port_net, 1)

            print(f"Connecting to node1 ({ip}:8333)...")
            node = connect_node(addr, timeout=5)
            if node:
                print("  ✓ Connected to node1")
                # Request blocks to sync
                print("  Requesting blocks to sync blockchain...")
            else:
                print("  ✗ Failed to connect to node1")
        except Exception as e:
            print(f"  ✗ Error connecting to node1: {e}")

    # Connect in background thread
    thread = threading.Thread(target=connect_to_peers, daemon=True)
    thread.start()


def run_server(port: int = 8080):
    """Run the visualization server"""
    # Initialize blockchain before starting server
    print("Initializing blockchain...")
    initialize_blockchain()

    # Verify initialization
    chain = get_chain()
    best_index = chain.get_best_index()
    height = getattr(chain, "best_height", -1)
    has_index = best_index is not None
    print(f"Blockchain initialized: height={height}, best_index={has_index}")

    # Start network node to receive blocks from peers
    start_network_node()

    server = HTTPServer(("0.0.0.0", port), VisualizationHandler)
    print(f"Visualization server running on http://0.0.0.0:{port}")
    server.serve_forever()


if __name__ == "__main__":
    port = int(os.environ.get("VISUALIZATION_PORT", "8080"))
    run_server(port)
