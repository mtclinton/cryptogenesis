"""
Message Handler

Handles incoming network messages.
Separated from state management - delegates to services for business logic.
"""

# Import Node from main network module file (not package to avoid circular import)
import importlib.util
import os
import sys
from typing import Any, Callable, Dict, Optional

from cryptogenesis.events import EventBus

network_file_path = os.path.join(os.path.dirname(__file__), "..", "network.py")
network_file_path = os.path.abspath(network_file_path)
spec = importlib.util.spec_from_file_location("network_module", network_file_path)
network_module = importlib.util.module_from_spec(spec)
sys.modules["network_module"] = network_module
spec.loader.exec_module(network_module)
Node = network_module.Node


class MessageHandler:
    """
    Message handler for processing incoming network messages.

    Handles message parsing and routing without managing state directly.
    Delegates business logic to services via events or callbacks.
    """

    def __init__(self, event_bus: Optional[EventBus] = None):
        """
        Initialize message handler.

        Args:
            event_bus: Optional EventBus instance for publishing events
        """
        self.event_bus = event_bus
        self._handlers: Dict[str, Callable[[Node, bytes], None]] = {}

    def register_handler(self, command: str, handler: Callable[[Node, bytes], None]):
        """
        Register a message handler for a command.

        Args:
            command: Message command string (e.g., "version", "tx", "block")
            handler: Handler function that takes (node, message_data) and returns None
        """
        self._handlers[command] = handler

    def handle_message(self, node: Node, command: str, message_data: bytes):
        """
        Handle an incoming message.

        Args:
            node: Node that sent the message
            command: Message command string
            message_data: Raw message data
        """
        try:
            # Look up handler
            handler = self._handlers.get(command)
            if handler:
                handler(node, message_data)
            else:
                # Unknown command - log or ignore
                print(f"Unknown message command: {command}")
        except Exception as e:
            print(f"Error handling message {command}: {e}")
            import traceback

            traceback.print_exc()

    def process_message(self, node: Node, command: str, message_data: bytes):
        """
        Process a message (alias for handle_message for compatibility).

        Args:
            node: Node that sent the message
            command: Message command string
            message_data: Raw message data
        """
        self.handle_message(node, command, message_data)
