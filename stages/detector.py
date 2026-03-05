"""USB Detector — listens for USB insertion events via udev (Linux) or WMI (Windows)."""
from __future__ import annotations
import sys
import threading
from core.events import EventBus, Event


class USBDetector:
    def __init__(self, bus: EventBus):
        self.bus = bus
        self._running = False
        self._thread: threading.Thread | None = None

    def _on_device_inserted(self, device_path: str, label: str, serial: str) -> None:
        self.bus.emit(Event("usb_inserted", {
            "usb_path": device_path,
            "usb_label": label,
            "usb_serial": serial,
        }))

    def start(self) -> None:
        self._running = True
        if sys.platform.startswith("linux"):
            self._thread = threading.Thread(target=self._linux_monitor, daemon=True)
        elif sys.platform == "win32":
            self._thread = threading.Thread(target=self._windows_monitor, daemon=True)
        else:
            raise RuntimeError(f"Unsupported platform: {sys.platform}")
        self._thread.start()

    def stop(self) -> None:
        self._running = False

    def _linux_monitor(self) -> None:
        import pyudev
        context = pyudev.Context()
        monitor = pyudev.Monitor.from_netlink(context)
        monitor.filter_by(subsystem="block", device_type="partition")
        for device in iter(monitor.poll, None):
            if not self._running:
                break
            if device.action == "add":
                path = device.device_node or ""
                label = device.get("ID_FS_LABEL", "UNKNOWN")
                serial = device.get("ID_SERIAL_SHORT", device.get("ID_SERIAL", "UNKNOWN"))
                self._on_device_inserted(path, label, serial)

    def _windows_monitor(self) -> None:
        import wmi
        c = wmi.WMI()
        watcher = c.Win32_VolumeChangeEvent.watch_for(EventType=2)  # 2 = insertion
        while self._running:
            try:
                event = watcher(timeout_ms=1000)
                if event:
                    drive = event.DriveName
                    self._on_device_inserted(drive, drive, "UNKNOWN")
            except Exception:
                pass
