# tests/test_detector.py
from unittest.mock import MagicMock, patch
from stages.detector import USBDetector
from core.events import EventBus, Event


def test_detector_emits_usb_inserted_event():
    bus = EventBus()
    events = []
    bus.subscribe("usb_inserted", lambda e: events.append(e))

    detector = USBDetector(bus)
    # Simulate the callback that udev/WMI would trigger
    detector._on_device_inserted(device_path="/dev/sdb1", label="KINGSTON", serial="ABC123")

    assert len(events) == 1
    assert events[0].data["usb_path"] == "/dev/sdb1"
    assert events[0].data["usb_label"] == "KINGSTON"
    assert events[0].data["usb_serial"] == "ABC123"
