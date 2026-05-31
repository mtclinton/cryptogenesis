"""
Network Service

Lifecycle facade over the P2P engine (cryptogenesis.network.protocol). Owns
starting/stopping the node, connecting peers, exposing the peer count, and
bridging engine peer connect/disconnect into NetworkState (which publishes
NetworkPeer*Event on the EventBus).
"""

from typing import Optional

from cryptogenesis.services.service_result import ServiceResult


class NetworkService:
    """Service for network operations."""

    def __init__(
        self,
        event_bus=None,
        blockchain_service=None,
        mempool_service=None,
        network_state=None,
    ):
        self.event_bus = event_bus
        self.blockchain_service = blockchain_service
        self.mempool_service = mempool_service
        self.network_state = network_state
        self._running = False

    def start(self, port: Optional[int] = None) -> ServiceResult:
        """Start the P2P node and bridge peer events into NetworkState."""
        from cryptogenesis.network import protocol

        protocol.set_node_callbacks(
            on_connected=self._on_peer_connected,
            on_disconnected=self._on_peer_disconnected,
        )

        success, error = protocol.start_node()
        self._running = success
        if not success:
            return ServiceResult(success=False, error=error or "Failed to start node")
        return ServiceResult(success=True, data={"running": True})

    def stop(self) -> ServiceResult:
        """Stop the P2P node and detach the engine callbacks."""
        from cryptogenesis.network import protocol

        if self._running:
            protocol.stop_node()
            self._running = False
        protocol.set_node_callbacks(None, None)
        return ServiceResult(success=True)

    def connect_peer(self, addr, timeout: int = 5) -> ServiceResult:
        """Open an outbound connection to a peer Address."""
        from cryptogenesis.network import protocol

        node = protocol.connect_node(addr, timeout=timeout)
        if node is None:
            return ServiceResult(success=False, error="Failed to connect to peer")
        return ServiceResult(success=True, data=node)

    def is_running(self) -> bool:
        return self._running

    def get_peer_count(self) -> int:
        from cryptogenesis.network import protocol

        with protocol.nodes_lock:
            return len(protocol.nodes)

    # -- engine bridge ---------------------------------------------------
    def _on_peer_connected(self, node):
        if self.network_state is not None:
            self.network_state.add_peer(node)

    def _on_peer_disconnected(self, node):
        if self.network_state is not None:
            self.network_state.remove_peer(node)
