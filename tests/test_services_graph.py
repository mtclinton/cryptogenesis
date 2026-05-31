"""
Phase 0 gate: the service graph constructs cleanly via dependency injection.

This is the regression net for the previously-untested services/state layer:
get_services() must wire all five services (with and without an EventBus) and
acyclically. Passes today; protects the wiring while the layer is migrated.
"""

from .context import cryptogenesis  # noqa: F401

from cryptogenesis.events import EventBus
from cryptogenesis.services import Services, get_services


def test_get_services_builds_full_graph():
    services = get_services(event_bus=EventBus())
    assert isinstance(services, Services)
    for name in (
        "blockchain_service",
        "wallet_service",
        "mining_service",
        "network_service",
        "mempool_service",
    ):
        assert getattr(services, name) is not None


def test_get_services_without_event_bus():
    services = get_services()
    assert services.blockchain_service is not None
    assert services.mempool_service is not None
