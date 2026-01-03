"""
Network Package

Network functionality separated from state management.
Contains network communication, peer management, and message handling.
"""

# Import new network classes
from cryptogenesis.network.network_manager import NetworkManager
from cryptogenesis.network.peer_manager import PeerManager
from cryptogenesis.network.message_handler import MessageHandler
from cryptogenesis.network.message_sender import MessageSender

# Re-export constants and types from the network.py module file for backward compatibility
# Import directly from the .py file to avoid circular imports
import importlib.util
import os
import sys

network_file_path = os.path.join(os.path.dirname(__file__), '..', 'network.py')
network_file_path = os.path.abspath(network_file_path)
spec = importlib.util.spec_from_file_location("network_module_file", network_file_path)
network_module_file = importlib.util.module_from_spec(spec)
sys.modules['network_module_file'] = network_module_file
spec.loader.exec_module(network_module_file)

# Re-export common types and constants
Address = network_module_file.Address
DEFAULT_PORT = network_module_file.DEFAULT_PORT
Inv = network_module_file.Inv
MessageHeader = network_module_file.MessageHeader
Node = network_module_file.Node
MESSAGE_START = network_module_file.MESSAGE_START
MSG_BLOCK = network_module_file.MSG_BLOCK
MSG_PRODUCT = network_module_file.MSG_PRODUCT
MSG_REVIEW = network_module_file.MSG_REVIEW
MSG_TABLE = network_module_file.MSG_TABLE
MSG_TX = network_module_file.MSG_TX
NODE_NETWORK = network_module_file.NODE_NETWORK

# Re-export functions (for backward compatibility)
add_address = network_module_file.add_address
connect_node = network_module_file.connect_node
find_node = network_module_file.find_node
relay_inventory = network_module_file.relay_inventory
set_network_mode = network_module_file.set_network_mode
get_network_mode = network_module_file.get_network_mode
start_node = network_module_file.start_node
stop_node = network_module_file.stop_node

__all__ = [
    "NetworkManager",
    "PeerManager",
    "MessageHandler",
    "MessageSender",
    "Address",
    "DEFAULT_PORT",
    "Inv",
    "MessageHeader",
    "Node",
    "MESSAGE_START",
    "MSG_BLOCK",
    "MSG_PRODUCT",
    "MSG_REVIEW",
    "MSG_TABLE",
    "MSG_TX",
    "NODE_NETWORK",
    "add_address",
    "connect_node",
    "find_node",
    "relay_inventory",
    "set_network_mode",
    "get_network_mode",
    "start_node",
    "stop_node",
]
