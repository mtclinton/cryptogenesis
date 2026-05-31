"""
Phase 6 pins for the mining service.

Mining is unified on the single bitcoin_miner loop: no private-network miner,
no global network-mode branch, and no reach into the top-level main module.
"""

import pathlib
import time

import pytest

from .context import cryptogenesis  # noqa: F401

from cryptogenesis.events import EventBus
from cryptogenesis.services import get_services

try:
    import ecdsa  # noqa: F401

    ECDSA = True
except Exception:  # pragma: no cover
    ECDSA = False

_PKG = pathlib.Path(cryptogenesis.__file__).parent


def test_mining_module_has_no_legacy_coupling():
    src = (_PKG / "mining.py").read_text()
    assert "import main" not in src
    assert "get_network_mode" not in src
    assert "bitcoin_miner_private_network" not in src
    assert "config_private" not in src


def test_mining_service_has_no_mode_branch():
    src = (_PKG / "services" / "mining_service.py").read_text()
    assert "get_network_mode" not in src
    assert "bitcoin_miner_private_network" not in src


@pytest.mark.skipif(not ECDSA, reason="mining needs ecdsa for key generation")
def test_mining_service_lifecycle():
    services = get_services(EventBus())
    mining = services.mining_service
    assert mining.is_mining() is False

    # With an empty global chain the worker idles, so this exercises the
    # start/stop lifecycle without depending on a block being found.
    result = mining.start_mining(node_id=1)
    assert result  # ServiceResult is truthy on success
    assert mining.is_mining() is True

    mining.stop_mining()
    assert mining.is_mining() is False
    time.sleep(0.2)  # let the idle worker observe the flag and exit
