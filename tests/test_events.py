# tests/test_events.py
from core.events import EventBus, Event


def test_subscribe_and_emit():
    bus = EventBus()
    received = []

    bus.subscribe("stage_start", lambda e: received.append(e))
    bus.emit(Event("stage_start", {"stage": "Scanner"}))

    assert len(received) == 1
    assert received[0].data["stage"] == "Scanner"


def test_multiple_subscribers():
    bus = EventBus()
    log = []

    bus.subscribe("progress", lambda e: log.append("A"))
    bus.subscribe("progress", lambda e: log.append("B"))
    bus.emit(Event("progress", {"pct": 50}))

    assert log == ["A", "B"]


def test_unsubscribed_event_is_silent():
    bus = EventBus()
    # No subscribers — should not raise
    bus.emit(Event("unknown_event", {}))


def test_event_name_and_data():
    e = Event("stage_done", {"stage": "Copier", "count": 3})
    assert e.name == "stage_done"
    assert e.data["count"] == 3
