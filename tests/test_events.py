"""
Phase 0 gate: EventBus publish/subscribe/unsubscribe + handler isolation.

The EventBus is the kept engine->visualizer seam, so its contract must hold
through the networking/state migration: type-routed delivery, base-Event
fan-out, working unsubscribe, and one failing handler never blocking others.
"""

from .context import cryptogenesis  # noqa: F401

from cryptogenesis.events import Event, EventBus


class _Ping(Event):
    pass


class _Pong(Event):
    pass


def test_publish_routes_by_type():
    bus = EventBus()
    received = []
    bus.subscribe(_Ping, received.append)
    bus.publish(_Ping("a"))
    bus.publish(_Pong("b"))  # no subscriber -> must be ignored
    assert len(received) == 1
    assert isinstance(received[0], _Ping)


def test_unsubscribe_stops_delivery():
    bus = EventBus()
    received = []
    bus.subscribe(_Ping, received.append)
    bus.unsubscribe(_Ping, received.append)
    bus.publish(_Ping("x"))
    assert received == []


def test_base_event_subscription_receives_all():
    bus = EventBus()
    seen = []
    bus.subscribe(Event, lambda e: seen.append(type(e).__name__))
    bus.publish(_Ping())
    bus.publish(_Pong())
    assert seen == ["_Ping", "_Pong"]


def test_handler_exception_is_isolated():
    bus = EventBus()
    delivered = []

    def boom(_event):
        raise RuntimeError("handler failure")

    bus.subscribe(_Ping, boom)
    bus.subscribe(_Ping, delivered.append)
    bus.publish(_Ping())  # must not raise despite boom()
    assert len(delivered) == 1
