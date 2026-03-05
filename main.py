"""Semper USB — entry point and daemon."""
from __future__ import annotations
import sys
import threading
from datetime import datetime
from pathlib import Path

import yaml

from core.events import EventBus, Event
from core.orchestrator import Orchestrator
from core.pipeline import PipelineContext
from stages.write_blocker import WriteBlocker
from stages.scanner import Scanner
from stages.triage import TriageEngine
from stages.copier import ForensicCopier
from stages.sorter import Sorter
from stages.packager import Packager
from stages.detector import USBDetector


def load_config(path: str = "config.yaml") -> dict:
    config_path = Path(__file__).parent / path
    with open(config_path) as f:
        return yaml.safe_load(f)


def run_pipeline(device_info: dict, config: dict) -> None:
    # Import GUI here to avoid hard dependency on tkinter at module level
    try:
        from gui.overlay import ScanOverlay
        overlay = ScanOverlay(device_info["usb_label"])
        overlay.run_in_thread()
        gui_available = True
    except ImportError:
        overlay = None
        gui_available = False

    bus = EventBus()

    if gui_available and overlay:
        bus.subscribe("stage_start", lambda e: overlay.push({"type": "stage_start", "stage": e.data["stage"]}))
        bus.subscribe("stage_done",  lambda e: overlay.push({"type": "stage_done",  "stage": e.data["stage"]}))
        bus.subscribe("pipeline_aborted", lambda e: overlay.push({"type": "aborted", "reason": e.data["reason"]}))

    mode = config.get("mode", "C")
    output_root = Path(config.get("output_dir", "~/semper-usb/output")).expanduser()
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    output_dir = output_root / f"{timestamp}_{device_info['usb_label']}"
    output_dir.mkdir(parents=True, exist_ok=True)

    ctx = PipelineContext(scan_start_time=datetime.now(), mode=mode)
    ctx.usb_path = device_info["usb_path"]
    ctx.usb_label = device_info["usb_label"]
    ctx.usb_serial = device_info["usb_serial"]
    ctx.output_dir = str(output_dir)

    stages = [
        WriteBlocker(),
        Scanner(config),
        TriageEngine(),
        ForensicCopier(),
        Sorter(),
        Packager(config),
    ]

    orch = Orchestrator(stages, bus)
    ctx = orch.run(ctx)

    if gui_available and overlay:
        overlay.push({
            "type": "complete",
            "total_files": len(ctx.scanned_files),
            "flagged": len(ctx.flagged_files),
            "categories": {k: len(v) for k, v in ctx.categorized.items()},
            "output_dir": str(output_dir),
        })


def on_usb_inserted(event: Event, config: dict) -> None:
    info = event.data
    try:
        from gui.confirm_dialog import ConfirmDialog
        dialog = ConfirmDialog(info["usb_label"], info["usb_serial"], info["usb_path"])
        approved = dialog.show()
    except ImportError:
        # No GUI available (headless/WSL without display) — auto-approve
        print(f"[Semper USB] USB detected: {info['usb_label']} — auto-approving (no GUI)")
        approved = True

    if approved:
        threading.Thread(target=run_pipeline, args=(info, config), daemon=True).start()


def main():
    config = load_config()
    bus = EventBus()
    detector = USBDetector(bus)
    bus.subscribe("usb_inserted", lambda e: on_usb_inserted(e, config))
    print("[Semper USB] Running. Waiting for USB insertion... (Ctrl+C to stop)")
    detector.start()
    try:
        detector._thread.join()
    except KeyboardInterrupt:
        print("\n[Semper USB] Stopped.")
        detector.stop()


if __name__ == "__main__":
    main()
