# Semper USB Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a cross-platform (Windows/Linux) Python daemon that auto-detects USB insertion, write-blocks the drive, scans for malware, forensically copies flagged files, sorts by threat category, and packages the results with a tkinter GUI overlay showing real-time progress.

**Architecture:** Modular pipeline — a core orchestrator iterates discrete `PipelineStage` objects in order, passing a shared `PipelineContext` dataclass between them. A pub/sub event bus decouples the GUI from the pipeline so either can run independently.

**Tech Stack:** Python 3.11+, pyudev (Linux), wmi (Windows), clamd, yara-python, vt-py, tkinter (stdlib), PyYAML, pytest

---

## Task 1: Project Scaffolding

**Files:**
- Create: `requirements.txt`
- Create: `config.yaml`
- Create: `main.py`
- Create: `tests/__init__.py`
- Create: `tests/conftest.py`
- Create: `stages/__init__.py`
- Create: `core/__init__.py`
- Create: `gui/__init__.py`
- Create: `rules/yara/.gitkeep`

**Step 1: Create requirements.txt**

```
clamd>=1.0.2
yara-python>=4.3.1
vt-py>=0.18.0
pyudev>=0.24.1; sys_platform == "linux"
wmi>=1.5.1; sys_platform == "win32"
PyYAML>=6.0.1
pytest>=8.0.0
pytest-mock>=3.12.0
```

**Step 2: Create config.yaml**

```yaml
output_dir: ~/semper-usb/output
mode: C                        # C = standard, D = forensic-grade
virustotal:
  enabled: false
  api_key: ""
  upload_files: false          # true = full upload, false = hash lookup only
yara_rules_dir: rules/yara
analyst_name: ""               # Used in D-mode chain of custody
clamav:
  socket: /var/run/clamav/clamd.ctl   # Linux default; Windows uses TCP
  host: 127.0.0.1
  port: 3310
```

**Step 3: Create main.py skeleton**

```python
"""Semper USB — entry point."""
import sys
import yaml
from pathlib import Path


def load_config(path: str = "config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def main():
    config = load_config()
    print("Semper USB starting...")
    # Daemon + GUI event loop wired in Task 10


if __name__ == "__main__":
    main()
```

**Step 4: Create tests/conftest.py**

```python
import pytest
from pathlib import Path
import tempfile, shutil


@pytest.fixture
def tmp_output(tmp_path):
    """Temporary output directory for each test."""
    return tmp_path / "output"


@pytest.fixture
def sample_config():
    return {
        "output_dir": "/tmp/semper-test",
        "mode": "C",
        "virustotal": {"enabled": False, "api_key": "", "upload_files": False},
        "yara_rules_dir": "rules/yara",
        "analyst_name": "Test Analyst",
        "clamav": {"socket": "/var/run/clamav/clamd.ctl", "host": "127.0.0.1", "port": 3310},
    }
```

**Step 5: Install dependencies and verify**

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
```
Expected: no tests collected, no errors.

**Step 6: Commit**

```bash
git add .
git commit -m "feat: initial project scaffold with config, requirements, and test setup"
```

---

## Task 2: Core — PipelineContext & PipelineStage

**Files:**
- Create: `core/pipeline.py`
- Create: `tests/test_pipeline.py`

**Step 1: Write the failing test**

```python
# tests/test_pipeline.py
from core.pipeline import PipelineContext, PipelineStage
from datetime import datetime


def test_pipeline_context_creation():
    ctx = PipelineContext(scan_start_time=datetime.now(), mode="C")
    assert ctx.errors == []
    assert ctx.flagged_files == []
    assert ctx.scanned_files == []


def test_pipeline_stage_run_raises_not_implemented():
    class BadStage(PipelineStage):
        pass

    stage = BadStage("bad")
    ctx = PipelineContext(scan_start_time=datetime.now(), mode="C")
    import pytest
    with pytest.raises(NotImplementedError):
        stage.run(ctx)


def test_pipeline_stage_name():
    class GoodStage(PipelineStage):
        def run(self, ctx):
            return ctx

    stage = GoodStage("Write Blocker")
    assert stage.name == "Write Blocker"
```

**Step 2: Run to verify failure**

```bash
pytest tests/test_pipeline.py -v
```
Expected: FAIL — `ModuleNotFoundError: No module named 'core.pipeline'`

**Step 3: Implement core/pipeline.py**

```python
"""Core pipeline primitives."""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal


@dataclass
class ScannedFile:
    path: str
    sha256: str
    md5: str
    size_bytes: int


@dataclass
class FlaggedFile(ScannedFile):
    engines: list[str] = field(default_factory=list)        # e.g. ["clamav", "yara"]
    signatures: list[str] = field(default_factory=list)     # e.g. ["Win.Ransomware.WannaCry"]
    category: str = ""                                       # assigned by triage
    original_timestamps: dict = field(default_factory=dict) # {created, modified, accessed}


@dataclass
class ScanReport:
    usb_label: str = ""
    usb_serial: str = ""
    total_files: int = 0
    flagged_count: int = 0
    categories: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


@dataclass
class PipelineContext:
    scan_start_time: datetime
    mode: Literal["C", "D"]

    # Set by detector
    usb_path: str = ""
    usb_label: str = ""
    usb_serial: str = ""
    mount_point: str = ""

    # Set by scanner
    scanned_files: list[ScannedFile] = field(default_factory=list)
    flagged_files: list[FlaggedFile] = field(default_factory=list)

    # Set by triage
    categorized: dict[str, list] = field(default_factory=dict)

    # Set by copier/sorter
    output_dir: str = ""
    directory_tree: str = ""

    # Set by packager
    zip_path: str = ""
    report: ScanReport = field(default_factory=ScanReport)

    # Runtime
    errors: list[str] = field(default_factory=list)


class PipelineStage:
    def __init__(self, name: str):
        self.name = name

    def run(self, ctx: PipelineContext) -> PipelineContext:
        raise NotImplementedError(f"{self.__class__.__name__} must implement run()")
```

**Step 4: Run tests to verify pass**

```bash
pytest tests/test_pipeline.py -v
```
Expected: 3 PASSED

**Step 5: Commit**

```bash
git add core/pipeline.py tests/test_pipeline.py
git commit -m "feat: add PipelineContext dataclass and PipelineStage base class"
```

---

## Task 3: Core — Event Bus

**Files:**
- Create: `core/events.py`
- Create: `tests/test_events.py`

**Step 1: Write the failing test**

```python
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
```

**Step 2: Run to verify failure**

```bash
pytest tests/test_events.py -v
```
Expected: FAIL — `ModuleNotFoundError`

**Step 3: Implement core/events.py**

```python
"""Simple synchronous pub/sub event bus."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class Event:
    name: str
    data: dict = field(default_factory=dict)


class EventBus:
    def __init__(self):
        self._subscribers: dict[str, list[Callable]] = {}

    def subscribe(self, event_name: str, callback: Callable[[Event], None]) -> None:
        self._subscribers.setdefault(event_name, []).append(callback)

    def emit(self, event: Event) -> None:
        for cb in self._subscribers.get(event.name, []):
            cb(event)
```

**Step 4: Run tests to verify pass**

```bash
pytest tests/test_events.py -v
```
Expected: 4 PASSED

**Step 5: Commit**

```bash
git add core/events.py tests/test_events.py
git commit -m "feat: add pub/sub EventBus for pipeline-to-GUI decoupling"
```

---

## Task 4: Core — Orchestrator

**Files:**
- Create: `core/orchestrator.py`
- Create: `tests/test_orchestrator.py`

**Step 1: Write the failing test**

```python
# tests/test_orchestrator.py
from core.orchestrator import Orchestrator
from core.pipeline import PipelineContext, PipelineStage
from core.events import EventBus, Event
from datetime import datetime


class DoubleStage(PipelineStage):
    """Test double — records calls and mutates context."""
    def __init__(self, name, key, value):
        super().__init__(name)
        self.key = key
        self.value = value

    def run(self, ctx):
        ctx.errors.append(f"{self.name} ran")
        return ctx


def make_ctx():
    return PipelineContext(scan_start_time=datetime.now(), mode="C")


def test_orchestrator_runs_all_stages():
    bus = EventBus()
    stages = [DoubleStage("A", "k", "v"), DoubleStage("B", "k2", "v2")]
    orch = Orchestrator(stages, bus)
    ctx = make_ctx()
    orch.run(ctx)
    assert ctx.errors == ["A ran", "B ran"]


def test_orchestrator_emits_stage_start_and_done():
    bus = EventBus()
    events = []
    bus.subscribe("stage_start", lambda e: events.append(("start", e.data["stage"])))
    bus.subscribe("stage_done", lambda e: events.append(("done", e.data["stage"])))

    orch = Orchestrator([DoubleStage("Scanner", "k", "v")], bus)
    orch.run(make_ctx())

    assert events == [("start", "Scanner"), ("done", "Scanner")]


def test_orchestrator_hard_aborts_on_abort_exception():
    from core.orchestrator import AbortPipeline

    class AbortingStage(PipelineStage):
        def run(self, ctx):
            raise AbortPipeline("Write block failed")

    class ShouldNotRunStage(PipelineStage):
        def run(self, ctx):
            ctx.errors.append("ran after abort")
            return ctx

    bus = EventBus()
    orch = Orchestrator([AbortingStage("WriteBlocker"), ShouldNotRunStage("Copier")], bus)
    ctx = make_ctx()
    orch.run(ctx)

    assert "ran after abort" not in ctx.errors
    assert any("Write block failed" in e for e in ctx.errors)
```

**Step 2: Run to verify failure**

```bash
pytest tests/test_orchestrator.py -v
```
Expected: FAIL — `ModuleNotFoundError`

**Step 3: Implement core/orchestrator.py**

```python
"""Pipeline orchestrator — runs stages in order, emits events."""
from __future__ import annotations
from core.pipeline import PipelineContext, PipelineStage
from core.events import EventBus, Event


class AbortPipeline(Exception):
    """Raised by a stage to hard-stop the pipeline (e.g. write-block failure)."""


class Orchestrator:
    def __init__(self, stages: list[PipelineStage], bus: EventBus):
        self.stages = stages
        self.bus = bus

    def run(self, ctx: PipelineContext) -> PipelineContext:
        for stage in self.stages:
            self.bus.emit(Event("stage_start", {"stage": stage.name}))
            try:
                ctx = stage.run(ctx)
                self.bus.emit(Event("stage_done", {"stage": stage.name}))
            except AbortPipeline as e:
                ctx.errors.append(str(e))
                self.bus.emit(Event("pipeline_aborted", {"stage": stage.name, "reason": str(e)}))
                break
            except Exception as e:
                ctx.errors.append(f"{stage.name}: {e}")
                self.bus.emit(Event("stage_error", {"stage": stage.name, "error": str(e)}))
        return ctx
```

**Step 4: Run tests to verify pass**

```bash
pytest tests/test_orchestrator.py -v
```
Expected: 3 PASSED

**Step 5: Commit**

```bash
git add core/orchestrator.py tests/test_orchestrator.py
git commit -m "feat: add Orchestrator with stage iteration, event emission, and AbortPipeline"
```

---

## Task 5: Stage — Triage Engine

**Files:**
- Create: `stages/triage.py`
- Create: `tests/test_triage.py`

> Note: Build Triage before Scanner because Scanner depends on knowing categories exist.

**Step 1: Write the failing test**

```python
# tests/test_triage.py
from stages.triage import TriageEngine, CATEGORY_PRIORITY
from core.pipeline import PipelineContext, FlaggedFile, ScannedFile
from datetime import datetime


def make_flagged(signatures: list[str], engines: list[str]) -> FlaggedFile:
    return FlaggedFile(
        path="/usb/evil.exe",
        sha256="abc123",
        md5="def456",
        size_bytes=1024,
        engines=engines,
        signatures=signatures,
    )


def make_ctx(flagged: list[FlaggedFile]) -> PipelineContext:
    ctx = PipelineContext(scan_start_time=datetime.now(), mode="C")
    ctx.flagged_files = flagged
    return ctx


def test_ransomware_takes_priority_over_pua():
    ctx = make_ctx([make_flagged(["Win.Ransomware.WannaCry", "Win.PUA.Adware"], ["clamav"])])
    triage = TriageEngine()
    ctx = triage.run(ctx)
    assert ctx.flagged_files[0].category == "ransomware"


def test_exploit_beats_malware():
    ctx = make_ctx([make_flagged(["CVE-2021-40444", "Win.Trojan.Generic"], ["clamav"])])
    triage = TriageEngine()
    ctx = triage.run(ctx)
    assert ctx.flagged_files[0].category == "exploit"


def test_unknown_flagged_catch_all():
    ctx = make_ctx([make_flagged(["unrecognized.sig.xyz"], ["virustotal"])])
    triage = TriageEngine()
    ctx = triage.run(ctx)
    assert ctx.flagged_files[0].category == "unknown_flagged"


def test_categorized_dict_built():
    flagged = [
        make_flagged(["Win.Ransomware.Locky"], ["clamav"]),
        make_flagged(["Obfuscated_PowerShell"], ["yara"]),
    ]
    ctx = make_ctx(flagged)
    triage = TriageEngine()
    ctx = triage.run(ctx)
    assert "ransomware" in ctx.categorized
    assert "suspicious_scripts" in ctx.categorized
```

**Step 2: Run to verify failure**

```bash
pytest tests/test_triage.py -v
```
Expected: FAIL — `ModuleNotFoundError`

**Step 3: Implement stages/triage.py**

```python
"""Triage Engine — maps detection signatures to threat categories."""
from __future__ import annotations
import re
from core.pipeline import PipelineContext, PipelineStage, FlaggedFile

# Priority order: index 0 = highest priority
CATEGORY_PRIORITY = [
    "ransomware",
    "exploit",
    "malware",
    "suspicious_scripts",
    "pua",
    "unknown_flagged",
]

# Patterns mapped to categories (checked in priority order)
SIGNATURE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("ransomware",        re.compile(r"ransomware|locker|cryptor", re.I)),
    ("exploit",           re.compile(r"CVE-\d{4}-\d+|exploit|shellcode", re.I)),
    ("malware",           re.compile(r"trojan|backdoor|rootkit|worm|virus|dropper", re.I)),
    ("suspicious_scripts",re.compile(r"obfuscat|powershell|base64.*vbs|vbs.*base64|macro", re.I)),
    ("pua",               re.compile(r"PUA|adware|riskware|unwanted", re.I)),
]


def _assign_category(signatures: list[str]) -> str:
    matched = set()
    for sig in signatures:
        for category, pattern in SIGNATURE_PATTERNS:
            if pattern.search(sig):
                matched.add(category)
    if not matched:
        return "unknown_flagged"
    # Return highest priority match
    for category in CATEGORY_PRIORITY:
        if category in matched:
            return category
    return "unknown_flagged"


class TriageEngine(PipelineStage):
    def __init__(self):
        super().__init__("Triage")

    def run(self, ctx: PipelineContext) -> PipelineContext:
        for f in ctx.flagged_files:
            f.category = _assign_category(f.signatures)

        ctx.categorized = {}
        for f in ctx.flagged_files:
            ctx.categorized.setdefault(f.category, []).append(f)

        return ctx
```

**Step 4: Run tests to verify pass**

```bash
pytest tests/test_triage.py -v
```
Expected: 4 PASSED

**Step 5: Commit**

```bash
git add stages/triage.py tests/test_triage.py
git commit -m "feat: add TriageEngine with priority-based threat category mapping"
```

---

## Task 6: Stage — Scanner

**Files:**
- Create: `stages/scanner.py`
- Create: `tests/test_scanner.py`

**Step 1: Write the failing test**

```python
# tests/test_scanner.py
from unittest.mock import MagicMock, patch
from stages.scanner import Scanner
from core.pipeline import PipelineContext
from datetime import datetime
import tempfile, os


def make_ctx(tmp_path: str) -> PipelineContext:
    ctx = PipelineContext(scan_start_time=datetime.now(), mode="C")
    ctx.mount_point = tmp_path
    return ctx


def test_scanner_flags_clamav_match(tmp_path, sample_config):
    # Write a dummy file
    f = tmp_path / "evil.exe"
    f.write_bytes(b"MZ" + b"\x00" * 100)

    ctx = make_ctx(str(tmp_path))

    with patch("stages.scanner.clamd") as mock_clamd:
        mock_sock = MagicMock()
        mock_clamd.ClamdUnixSocket.return_value = mock_sock
        mock_sock.scan.return_value = {
            str(f): ("FOUND", "Win.Trojan.Generic-1234")
        }
        scanner = Scanner(sample_config)
        ctx = scanner.run(ctx)

    assert len(ctx.flagged_files) == 1
    assert ctx.flagged_files[0].signatures == ["Win.Trojan.Generic-1234"]
    assert "clamav" in ctx.flagged_files[0].engines


def test_scanner_clean_file_not_flagged(tmp_path, sample_config):
    f = tmp_path / "clean.txt"
    f.write_text("hello world")

    ctx = make_ctx(str(tmp_path))

    with patch("stages.scanner.clamd") as mock_clamd:
        mock_sock = MagicMock()
        mock_clamd.ClamdUnixSocket.return_value = mock_sock
        mock_sock.scan.return_value = {str(f): ("OK", None)}
        scanner = Scanner(sample_config)
        ctx = scanner.run(ctx)

    assert len(ctx.flagged_files) == 0
    assert len(ctx.scanned_files) == 1


def test_scanner_clamav_unavailable_continues(tmp_path, sample_config):
    f = tmp_path / "file.txt"
    f.write_text("data")
    ctx = make_ctx(str(tmp_path))

    with patch("stages.scanner.clamd") as mock_clamd:
        mock_clamd.ClamdUnixSocket.side_effect = Exception("ClamAV not running")
        scanner = Scanner(sample_config)
        ctx = scanner.run(ctx)

    assert any("ClamAV" in e for e in ctx.errors)
    assert len(ctx.scanned_files) == 1   # still walked the files
```

**Step 2: Run to verify failure**

```bash
pytest tests/test_scanner.py -v
```
Expected: FAIL — `ModuleNotFoundError`

**Step 3: Implement stages/scanner.py**

```python
"""Scanner stage — ClamAV + YARA + optional VirusTotal."""
from __future__ import annotations
import hashlib
import os
from pathlib import Path

import clamd
import yara

from core.pipeline import PipelineContext, PipelineStage, ScannedFile, FlaggedFile


def _hash_file(path: str) -> tuple[str, str]:
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
            md5.update(chunk)
    return sha256.hexdigest(), md5.hexdigest()


def _get_timestamps(path: str) -> dict:
    stat = os.stat(path)
    return {
        "modified": stat.st_mtime,
        "accessed": stat.st_atime,
    }


class Scanner(PipelineStage):
    def __init__(self, config: dict):
        super().__init__("Scanner")
        self.config = config

    def _build_clamav(self):
        cfg = self.config.get("clamav", {})
        socket = cfg.get("socket", "/var/run/clamav/clamd.ctl")
        if os.path.exists(socket):
            return clamd.ClamdUnixSocket(socket)
        return clamd.ClamdNetworkSocket(cfg.get("host", "127.0.0.1"), cfg.get("port", 3310))

    def _load_yara_rules(self) -> yara.Rules | None:
        rules_dir = Path(self.config.get("yara_rules_dir", "rules/yara"))
        yar_files = list(rules_dir.glob("*.yar")) + list(rules_dir.glob("*.yara"))
        if not yar_files:
            return None
        filepaths = {f.stem: str(f) for f in yar_files}
        return yara.compile(filepaths=filepaths)

    def run(self, ctx: PipelineContext) -> PipelineContext:
        # Initialize engines
        clam = None
        try:
            clam = self._build_clamav()
            clam.ping()
        except Exception as e:
            ctx.errors.append(f"ClamAV unavailable: {e}. Skipping ClamAV scan.")
            clam = None

        rules = None
        try:
            rules = self._load_yara_rules()
        except Exception as e:
            ctx.errors.append(f"YARA rules load failed: {e}. Skipping YARA scan.")

        vt_enabled = self.config.get("virustotal", {}).get("enabled", False)

        # Walk mount point
        mount = Path(ctx.mount_point)
        all_files = [p for p in mount.rglob("*") if p.is_file()]
        total = len(all_files)

        for i, filepath in enumerate(all_files):
            path_str = str(filepath)
            try:
                sha256, md5 = _hash_file(path_str)
                size = filepath.stat().st_size
                timestamps = _get_timestamps(path_str)
            except (PermissionError, OSError) as e:
                ctx.errors.append(f"Cannot read {path_str}: {e}")
                continue

            scanned = ScannedFile(path=path_str, sha256=sha256, md5=md5, size_bytes=size)
            ctx.scanned_files.append(scanned)

            matched_engines: list[str] = []
            matched_sigs: list[str] = []

            # ClamAV
            if clam:
                try:
                    result = clam.scan(path_str)
                    status, sig = result.get(path_str, ("OK", None))
                    if status == "FOUND" and sig:
                        matched_engines.append("clamav")
                        matched_sigs.append(sig)
                except Exception as e:
                    ctx.errors.append(f"ClamAV scan error on {path_str}: {e}")

            # YARA
            if rules:
                try:
                    matches = rules.match(path_str)
                    if matches:
                        matched_engines.append("yara")
                        matched_sigs.extend(m.rule for m in matches)
                except Exception as e:
                    ctx.errors.append(f"YARA scan error on {path_str}: {e}")

            # VirusTotal (hash lookup only unless upload_files=true)
            if vt_enabled:
                matched_engines, matched_sigs = self._vt_check(
                    path_str, sha256, matched_engines, matched_sigs, ctx
                )

            if matched_engines:
                ctx.flagged_files.append(FlaggedFile(
                    path=path_str,
                    sha256=sha256,
                    md5=md5,
                    size_bytes=size,
                    engines=matched_engines,
                    signatures=matched_sigs,
                    original_timestamps=timestamps,
                ))

        return ctx

    def _vt_check(self, path, sha256, engines, sigs, ctx):
        try:
            import vt
            api_key = self.config["virustotal"]["api_key"]
            upload = self.config["virustotal"].get("upload_files", False)
            with vt.Client(api_key) as client:
                if upload:
                    with open(path, "rb") as f:
                        analysis = client.scan_file(f, size=os.path.getsize(path))
                    file_obj = client.get_object(f"/analyses/{analysis.id}")
                else:
                    file_obj = client.get_object(f"/files/{sha256}")

                stats = file_obj.last_analysis_stats
                malicious = stats.get("malicious", 0)
                if malicious >= 3:
                    engines.append("virustotal")
                    sigs.append(f"VT:{malicious}/70")
        except Exception as e:
            ctx.errors.append(f"VirusTotal check failed for {path}: {e}. Marked vt_skipped.")
        return engines, sigs
```

**Step 4: Run tests to verify pass**

```bash
pytest tests/test_scanner.py -v
```
Expected: 3 PASSED

**Step 5: Commit**

```bash
git add stages/scanner.py tests/test_scanner.py
git commit -m "feat: add Scanner stage with ClamAV, YARA, and optional VirusTotal"
```

---

## Task 7: Stage — Forensic Copier & Sorter

**Files:**
- Create: `stages/copier.py`
- Create: `stages/sorter.py`
- Create: `tests/test_copier.py`
- Create: `tests/test_sorter.py`

**Step 1: Write the failing tests**

```python
# tests/test_copier.py
from stages.copier import ForensicCopier
from core.pipeline import PipelineContext, FlaggedFile, ScannedFile
from datetime import datetime
from pathlib import Path


def make_ctx(flagged, mount, output):
    ctx = PipelineContext(scan_start_time=datetime.now(), mode="C")
    ctx.flagged_files = flagged
    ctx.mount_point = str(mount)
    ctx.output_dir = str(output)
    return ctx


def test_copier_copies_flagged_files(tmp_path):
    # Create a fake USB file
    usb = tmp_path / "usb"
    usb.mkdir()
    evil = usb / "evil.exe"
    evil.write_bytes(b"EVIL")

    out = tmp_path / "output"
    out.mkdir()

    flagged = [FlaggedFile(
        path=str(evil), sha256="abc", md5="def",
        size_bytes=4, category="malware",
        signatures=["Win.Trojan.Generic"],
        engines=["clamav"],
    )]

    ctx = make_ctx(flagged, usb, out)
    copier = ForensicCopier()
    ctx = copier.run(ctx)

    # File should exist somewhere under output
    copied = list(out.rglob("evil.exe"))
    assert len(copied) == 1


def test_copier_builds_directory_tree(tmp_path):
    usb = tmp_path / "usb"
    usb.mkdir()
    (usb / "readme.txt").write_text("hello")
    (usb / "evil.exe").write_bytes(b"bad")

    out = tmp_path / "output"
    out.mkdir()

    ctx = make_ctx([], usb, out)
    copier = ForensicCopier()
    ctx = copier.run(ctx)

    assert "readme.txt" in ctx.directory_tree
    assert "evil.exe" in ctx.directory_tree
```

```python
# tests/test_sorter.py
from stages.sorter import Sorter
from core.pipeline import PipelineContext, FlaggedFile
from datetime import datetime
from pathlib import Path


def make_flagged(path, category, signature):
    return FlaggedFile(
        path=path, sha256="x", md5="y", size_bytes=10,
        category=category, signatures=[signature], engines=["clamav"],
    )


def test_sorter_creates_category_subdirs(tmp_path):
    out = tmp_path / "output"
    out.mkdir()
    src = tmp_path / "src"
    src.mkdir()
    evil = src / "evil.exe"
    evil.write_bytes(b"BAD")

    ctx = PipelineContext(scan_start_time=datetime.now(), mode="C")
    ctx.output_dir = str(out)
    ctx.flagged_files = [make_flagged(str(evil), "malware", "Win.Trojan.Generic")]
    ctx.categorized = {"malware": ctx.flagged_files}

    sorter = Sorter()
    ctx = sorter.run(ctx)

    expected = out / "malware" / "Win.Trojan.Generic"
    assert expected.is_dir()
    assert (expected / "evil.exe").exists()
```

**Step 2: Run to verify failure**

```bash
pytest tests/test_copier.py tests/test_sorter.py -v
```
Expected: FAIL — `ModuleNotFoundError`

**Step 3: Implement stages/copier.py**

```python
"""Forensic Copier — copies flagged files preserving timestamps, builds directory tree."""
from __future__ import annotations
import shutil
from pathlib import Path
from core.pipeline import PipelineContext, PipelineStage


def _build_tree(mount_point: str) -> str:
    lines = []
    root = Path(mount_point)
    for p in sorted(root.rglob("*")):
        indent = "  " * (len(p.relative_to(root).parts) - 1)
        lines.append(f"{indent}{p.name}{'/' if p.is_dir() else ''}")
    return "\n".join(lines)


class ForensicCopier(PipelineStage):
    def __init__(self):
        super().__init__("Copier")

    def run(self, ctx: PipelineContext) -> PipelineContext:
        out = Path(ctx.output_dir)
        out.mkdir(parents=True, exist_ok=True)

        for f in ctx.flagged_files:
            src = Path(f.path)
            dest = out / src.name
            try:
                shutil.copy2(src, dest)   # copy2 preserves timestamps
            except Exception as e:
                ctx.errors.append(f"Copy failed for {f.path}: {e}")

        ctx.directory_tree = _build_tree(ctx.mount_point)
        return ctx
```

**Step 4: Implement stages/sorter.py**

```python
"""Sorter — organises copied files into /category/signature/ directories."""
from __future__ import annotations
import shutil
import re
from pathlib import Path
from core.pipeline import PipelineContext, PipelineStage, FlaggedFile


def _safe_dirname(name: str) -> str:
    """Sanitise signature name for use as a directory name."""
    return re.sub(r"[^\w\-.]", "_", name)[:64]


class Sorter(PipelineStage):
    def __init__(self):
        super().__init__("Sorter")

    def run(self, ctx: PipelineContext) -> PipelineContext:
        out = Path(ctx.output_dir)

        for f in ctx.flagged_files:
            src = Path(f.path)
            primary_sig = _safe_dirname(f.signatures[0]) if f.signatures else "unknown"
            dest_dir = out / f.category / primary_sig
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest = dest_dir / src.name

            try:
                if src.exists():
                    shutil.copy2(src, dest)
                elif (out / src.name).exists():
                    shutil.move(str(out / src.name), dest)
            except Exception as e:
                ctx.errors.append(f"Sort failed for {f.path}: {e}")

        return ctx
```

**Step 5: Run tests to verify pass**

```bash
pytest tests/test_copier.py tests/test_sorter.py -v
```
Expected: 3 PASSED

**Step 6: Commit**

```bash
git add stages/copier.py stages/sorter.py tests/test_copier.py tests/test_sorter.py
git commit -m "feat: add ForensicCopier and Sorter stages with timestamp preservation"
```

---

## Task 8: Stage — Packager (C-mode and D-mode)

**Files:**
- Create: `stages/packager.py`
- Create: `tests/test_packager.py`

**Step 1: Write the failing test**

```python
# tests/test_packager.py
import json, zipfile
from stages.packager import Packager
from core.pipeline import PipelineContext, FlaggedFile, ScanReport
from datetime import datetime
from pathlib import Path


def make_ctx(tmp_path, mode="C"):
    out = tmp_path / "output"
    out.mkdir()
    # Plant a fake sorted file
    cat_dir = out / "malware" / "Win.Trojan.Generic"
    cat_dir.mkdir(parents=True)
    (cat_dir / "evil.exe").write_bytes(b"BAD")
    (out / "directory_tree.txt").write_text("evil.exe\n")

    ctx = PipelineContext(scan_start_time=datetime.now(), mode=mode)
    ctx.output_dir = str(out)
    ctx.usb_label = "TEST_USB"
    ctx.usb_serial = "SERIAL123"
    ctx.flagged_files = [FlaggedFile(
        path="/usb/evil.exe", sha256="abc123", md5="def456",
        size_bytes=3, category="malware",
        signatures=["Win.Trojan.Generic"], engines=["clamav"],
        original_timestamps={"modified": 0, "accessed": 0},
    )]
    ctx.report = ScanReport(
        usb_label="TEST_USB", usb_serial="SERIAL123",
        total_files=1, flagged_count=1,
        categories={"malware": 1},
    )
    return ctx


def test_packager_creates_zip(tmp_path, sample_config):
    ctx = make_ctx(tmp_path)
    packager = Packager(sample_config)
    ctx = packager.run(ctx)
    assert ctx.zip_path
    assert Path(ctx.zip_path).exists()


def test_packager_zip_contains_report(tmp_path, sample_config):
    ctx = make_ctx(tmp_path)
    packager = Packager(sample_config)
    ctx = packager.run(ctx)
    with zipfile.ZipFile(ctx.zip_path) as z:
        names = z.namelist()
    assert any("report.json" in n for n in names)


def test_packager_d_mode_adds_coc(tmp_path, sample_config):
    sample_config["analyst_name"] = "Test Analyst"
    ctx = make_ctx(tmp_path, mode="D")
    packager = Packager(sample_config)
    ctx = packager.run(ctx)
    with zipfile.ZipFile(ctx.zip_path) as z:
        names = z.namelist()
    assert any("chain_of_custody" in n for n in names)
    assert any("volume_manifest" in n for n in names)
```

**Step 2: Run to verify failure**

```bash
pytest tests/test_packager.py -v
```
Expected: FAIL — `ModuleNotFoundError`

**Step 3: Implement stages/packager.py**

```python
"""Packager — zips output directory with report. C-mode default, D-mode forensic."""
from __future__ import annotations
import hashlib
import json
import zipfile
from datetime import datetime
from pathlib import Path

from core.pipeline import PipelineContext, PipelineStage, ScanReport


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class Packager(PipelineStage):
    def __init__(self, config: dict):
        super().__init__("Packager")
        self.config = config

    def run(self, ctx: PipelineContext) -> PipelineContext:
        out = Path(ctx.output_dir)

        # Write report.json
        report_data = {
            "usb_label": ctx.usb_label,
            "usb_serial": ctx.usb_serial,
            "scan_time": ctx.scan_start_time.isoformat(),
            "total_files": len(ctx.scanned_files),
            "flagged_count": len(ctx.flagged_files),
            "categories": {k: len(v) for k, v in ctx.categorized.items()},
            "errors": ctx.errors,
            "flagged_files": [
                {
                    "path": f.path,
                    "sha256": f.sha256,
                    "md5": f.md5,
                    "size_bytes": f.size_bytes,
                    "category": f.category,
                    "signatures": f.signatures,
                    "engines": f.engines,
                    "timestamps": f.original_timestamps,
                }
                for f in ctx.flagged_files
            ],
        }
        report_path = out / "report.json"
        report_path.write_text(json.dumps(report_data, indent=2))

        # D-mode extras
        if ctx.mode == "D":
            self._write_d_mode_artifacts(ctx, out)

        # Zip everything
        zip_path = out / "semper_usb_package.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for file in out.rglob("*"):
                if file.is_file() and file != zip_path:
                    zf.write(file, file.relative_to(out))

        ctx.zip_path = str(zip_path)
        return ctx

    def _write_d_mode_artifacts(self, ctx: PipelineContext, out: Path) -> None:
        analyst = self.config.get("analyst_name", "Unknown")
        now = datetime.now().isoformat()

        # Chain of custody
        coc = (
            f"CHAIN OF CUSTODY\n"
            f"================\n"
            f"Analyst:      {analyst}\n"
            f"Date/Time:    {now}\n"
            f"USB Label:    {ctx.usb_label}\n"
            f"USB Serial:   {ctx.usb_serial}\n"
            f"Tool:         Semper USB\n"
            f"Scan Start:   {ctx.scan_start_time.isoformat()}\n"
        )
        (out / "chain_of_custody.txt").write_text(coc)

        # Volume manifest
        lines = []
        for f in ctx.scanned_files:
            lines.append(f"{f.sha256}  {f.path}")
        (out / "volume_manifest.sha256").write_text("\n".join(lines))
```

**Step 4: Run tests to verify pass**

```bash
pytest tests/test_packager.py -v
```
Expected: 3 PASSED

**Step 5: Commit**

```bash
git add stages/packager.py tests/test_packager.py
git commit -m "feat: add Packager stage with C-mode zip+report and D-mode forensic artifacts"
```

---

## Task 9: Stage — Write Blocker

**Files:**
- Create: `stages/write_blocker.py`
- Create: `tests/test_write_blocker.py`

> Note: Write-block failure is a hard abort — uses `AbortPipeline`.

**Step 1: Write the failing test**

```python
# tests/test_write_blocker.py
import sys
from unittest.mock import patch, MagicMock
from core.orchestrator import AbortPipeline
from core.pipeline import PipelineContext
from datetime import datetime
import pytest


def make_ctx():
    ctx = PipelineContext(scan_start_time=datetime.now(), mode="C")
    ctx.usb_path = "/dev/sdb1"
    ctx.usb_label = "TEST"
    return ctx


@pytest.mark.skipif(sys.platform != "linux", reason="Linux only")
def test_linux_write_block_sets_mount_point():
    from stages.write_blocker import WriteBlocker
    ctx = make_ctx()
    with patch("stages.write_blocker.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        blocker = WriteBlocker()
        ctx = blocker.run(ctx)
    assert ctx.mount_point != ""


@pytest.mark.skipif(sys.platform != "linux", reason="Linux only")
def test_linux_write_block_aborts_on_failure():
    from stages.write_blocker import WriteBlocker
    ctx = make_ctx()
    with patch("stages.write_blocker.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1, stderr="permission denied")
        blocker = WriteBlocker()
        with pytest.raises(AbortPipeline):
            blocker.run(ctx)
```

**Step 2: Run to verify failure**

```bash
pytest tests/test_write_blocker.py -v
```
Expected: FAIL — `ModuleNotFoundError`

**Step 3: Implement stages/write_blocker.py**

```python
"""Write Blocker — mounts USB read-only before any scanning begins."""
from __future__ import annotations
import subprocess
import sys
import tempfile
import os
from pathlib import Path
from core.pipeline import PipelineContext, PipelineStage
from core.orchestrator import AbortPipeline


class WriteBlocker(PipelineStage):
    def __init__(self):
        super().__init__("Write Blocker")

    def run(self, ctx: PipelineContext) -> PipelineContext:
        if sys.platform.startswith("linux"):
            return self._linux_block(ctx)
        elif sys.platform == "win32":
            return self._windows_block(ctx)
        else:
            raise AbortPipeline(f"Unsupported platform: {sys.platform}")

    def _linux_block(self, ctx: PipelineContext) -> PipelineContext:
        mount_point = tempfile.mkdtemp(prefix="semper_usb_")
        result = subprocess.run(
            ["mount", "-o", "ro", ctx.usb_path, mount_point],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            raise AbortPipeline(
                f"Write-block failed: could not mount {ctx.usb_path} read-only. "
                f"stderr: {result.stderr}. ABORTING — do not proceed without forensic integrity."
            )
        ctx.mount_point = mount_point
        return ctx

    def _windows_block(self, ctx: PipelineContext) -> PipelineContext:
        """
        Set WriteProtect registry key for USB storage, then use the drive letter directly.
        Requires admin privileges.
        """
        try:
            import winreg
            key_path = r"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies"
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "WriteProtect", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
        except Exception as e:
            raise AbortPipeline(
                f"Write-block failed on Windows: {e}. "
                "Run Semper USB as Administrator."
            )
        ctx.mount_point = ctx.usb_path   # On Windows, use drive letter directly
        return ctx
```

**Step 4: Run tests**

```bash
pytest tests/test_write_blocker.py -v
```
Expected: 2 PASSED (on Linux), skipped on Windows

**Step 5: Commit**

```bash
git add stages/write_blocker.py tests/test_write_blocker.py
git commit -m "feat: add WriteBlocker stage with read-only mount (Linux) and registry lock (Windows)"
```

---

## Task 10: Stage — USB Detector

**Files:**
- Create: `stages/detector.py`
- Create: `tests/test_detector.py`

> Note: Detector runs as a daemon loop — test the callback/event mechanism, not the OS-level detection.

**Step 1: Write the failing test**

```python
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
```

**Step 2: Run to verify failure**

```bash
pytest tests/test_detector.py -v
```
Expected: FAIL — `ModuleNotFoundError`

**Step 3: Implement stages/detector.py**

```python
"""USB Detector — listens for USB insertion events via udev (Linux) or WMI (Windows)."""
from __future__ import annotations
import sys
import threading
from core.events import EventBus, Event
from core.pipeline import PipelineStage


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
```

**Step 4: Run tests**

```bash
pytest tests/test_detector.py -v
```
Expected: 1 PASSED

**Step 5: Commit**

```bash
git add stages/detector.py tests/test_detector.py
git commit -m "feat: add USBDetector with udev (Linux) and WMI (Windows) event monitoring"
```

---

## Task 11: GUI — Confirm Dialog & Progress Overlay

**Files:**
- Create: `gui/confirm_dialog.py`
- Create: `gui/overlay.py`

> Note: tkinter cannot be unit tested meaningfully. Build and manually smoke-test with the checklist below.

**Step 1: Implement gui/confirm_dialog.py**

```python
"""Confirm dialog — shown when USB insertion detected."""
from __future__ import annotations
import tkinter as tk
from tkinter import ttk


class ConfirmDialog:
    def __init__(self, usb_label: str, usb_serial: str, usb_path: str):
        self.result = False
        self._root = tk.Tk()
        self._root.title("Semper USB — Device Detected")
        self._root.resizable(False, False)
        self._build(usb_label, usb_serial, usb_path)

    def _build(self, label, serial, path):
        root = self._root
        tk.Label(root, text="USB Device Detected", font=("Helvetica", 14, "bold")).pack(pady=(16, 4))
        frame = tk.Frame(root)
        frame.pack(padx=24, pady=8)
        for key, val in [("Label", label), ("Serial", serial), ("Path", path)]:
            tk.Label(frame, text=f"{key}:", anchor="w", width=8).grid(sticky="w")
            tk.Label(frame, text=val, anchor="w").grid(row=frame.grid_size()[1]-1, column=1, sticky="w")
        tk.Label(root, text="Semper USB will mount this drive read-only\nand scan for malicious content.",
                 justify="center").pack(pady=8)
        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=(4, 16))
        tk.Button(btn_frame, text="Scan Now", width=12, command=self._scan).pack(side="left", padx=8)
        tk.Button(btn_frame, text="Ignore",   width=12, command=self._ignore).pack(side="left", padx=8)

    def _scan(self):
        self.result = True
        self._root.destroy()

    def _ignore(self):
        self.result = False
        self._root.destroy()

    def show(self) -> bool:
        self._root.mainloop()
        return self.result
```

**Step 2: Implement gui/overlay.py**

```python
"""Scan progress overlay — persistent window shown during pipeline execution."""
from __future__ import annotations
import queue
import threading
import tkinter as tk
from tkinter import ttk
import subprocess, sys
from datetime import datetime

STAGES = ["Write Blocker", "Scanner", "Triage", "Copier", "Sorter", "Packager"]


class ScanOverlay:
    def __init__(self, usb_label: str):
        self._q: queue.Queue = queue.Queue()
        self._label = usb_label
        self._start = datetime.now()
        self._root: tk.Tk | None = None

    def build(self):
        root = tk.Tk()
        self._root = root
        root.title("Semper USB")
        root.resizable(False, False)

        tk.Label(root, text=f"Scanning {self._label}", font=("Helvetica", 13, "bold")).pack(pady=(12, 4))
        ttk.Separator(root).pack(fill="x", padx=8)

        self._stage_label = tk.Label(root, text="Initializing...", anchor="w")
        self._stage_label.pack(padx=16, pady=(8, 0), fill="x")

        self._progress = ttk.Progressbar(root, length=340, mode="determinate")
        self._progress.pack(padx=16, pady=4)

        self._pct_label = tk.Label(root, text="0%", anchor="e")
        self._pct_label.pack(padx=16, fill="x")

        ttk.Separator(root).pack(fill="x", padx=8, pady=4)

        self._crumb_vars = {}
        for stage in STAGES:
            var = tk.StringVar(value=f"  {stage}")
            self._crumb_vars[stage] = var
            tk.Label(root, textvariable=var, anchor="w").pack(padx=24, fill="x")

        ttk.Separator(root).pack(fill="x", padx=8, pady=4)
        self._elapsed_label = tk.Label(root, text="Elapsed: 00:00:00", anchor="w")
        self._elapsed_label.pack(padx=16, pady=(0, 12), fill="x")

        root.after(100, self._poll)
        root.after(1000, self._tick)
        root.mainloop()

    def _tick(self):
        elapsed = datetime.now() - self._start
        secs = int(elapsed.total_seconds())
        h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
        self._elapsed_label.config(text=f"Elapsed: {h:02d}:{m:02d}:{s:02d}")
        if self._root:
            self._root.after(1000, self._tick)

    def _poll(self):
        try:
            while True:
                event = self._q.get_nowait()
                self._handle(event)
        except queue.Empty:
            pass
        if self._root:
            self._root.after(100, self._poll)

    def _handle(self, event: dict):
        kind = event.get("type")
        if kind == "stage_start":
            stage = event["stage"]
            self._stage_label.config(text=f"Stage: {stage}...")
            for s, var in self._crumb_vars.items():
                if s == stage:
                    var.set(f"  > {s}")
        elif kind == "stage_done":
            stage = event["stage"]
            self._crumb_vars[stage].set(f"  [done] {stage}")
        elif kind == "progress":
            pct = event.get("pct", 0)
            self._progress["value"] = pct
            self._pct_label.config(text=f"{pct:.0f}%  ({event.get('current',0)}/{event.get('total',0)})")
        elif kind == "complete":
            self._show_summary(event)
        elif kind == "aborted":
            self._show_abort(event)

    def _show_summary(self, event: dict):
        if not self._root:
            return
        for widget in self._root.winfo_children():
            widget.destroy()
        tk.Label(self._root, text="Scan Complete", font=("Helvetica", 14, "bold")).pack(pady=(16, 4))
        tk.Label(self._root, text=f"{event.get('total_files', 0)} files scanned   |   {event.get('flagged', 0)} threats found").pack()
        for cat, count in event.get("categories", {}).items():
            tk.Label(self._root, text=f"  {cat}: {count}", anchor="w").pack(padx=24, fill="x")
        tk.Label(self._root, text=f"\nOutput:\n{event.get('output_dir','')}", justify="left").pack(padx=16)
        btn = tk.Frame(self._root)
        btn.pack(pady=12)
        output_dir = event.get("output_dir", "")
        tk.Button(btn, text="Open Output Folder", command=lambda: self._open_folder(output_dir)).pack(side="left", padx=8)
        tk.Button(btn, text="Dismiss", command=self._root.destroy).pack(side="left", padx=8)

    def _show_abort(self, event: dict):
        if not self._root:
            return
        for widget in self._root.winfo_children():
            widget.destroy()
        tk.Label(self._root, text="SCAN ABORTED", font=("Helvetica", 14, "bold"), fg="red").pack(pady=16)
        tk.Label(self._root, text=event.get("reason", "Unknown error"), wraplength=320).pack(padx=16)
        tk.Button(self._root, text="Dismiss", command=self._root.destroy).pack(pady=12)

    def _open_folder(self, path: str):
        if sys.platform == "win32":
            subprocess.Popen(["explorer", path])
        else:
            subprocess.Popen(["xdg-open", path])

    def push(self, event: dict):
        """Thread-safe — call from pipeline thread."""
        self._q.put(event)

    def run_in_thread(self) -> threading.Thread:
        t = threading.Thread(target=self.build, daemon=True)
        t.start()
        return t
```

**Step 3: Manual smoke test checklist**

Run: `python -c "from gui.confirm_dialog import ConfirmDialog; d = ConfirmDialog('KINGSTON', 'ABC123', '/dev/sdb1'); print(d.show())"`

- [ ] Window appears with correct label, serial, path
- [ ] "Scan Now" returns True
- [ ] "Ignore" returns False
- [ ] Window closes after button click

**Step 4: Commit**

```bash
git add gui/confirm_dialog.py gui/overlay.py
git commit -m "feat: add tkinter confirm dialog and scan progress overlay with stage breadcrumbs"
```

---

## Task 12: Wire Everything Together in main.py

**Files:**
- Modify: `main.py`

**Step 1: Implement main.py**

```python
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
from gui.confirm_dialog import ConfirmDialog
from gui.overlay import ScanOverlay


def load_config(path: str = "config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def run_pipeline(device_info: dict, config: dict) -> None:
    bus = EventBus()
    overlay = ScanOverlay(device_info["usb_label"])
    overlay.run_in_thread()

    # Wire bus events to overlay
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

    overlay.push({
        "type": "complete",
        "total_files": len(ctx.scanned_files),
        "flagged": len(ctx.flagged_files),
        "categories": {k: len(v) for k, v in ctx.categorized.items()},
        "output_dir": str(output_dir),
    })


def on_usb_inserted(event: Event, config: dict) -> None:
    info = event.data
    dialog = ConfirmDialog(info["usb_label"], info["usb_serial"], info["usb_path"])
    if dialog.show():
        threading.Thread(target=run_pipeline, args=(info, config), daemon=True).start()


def main():
    config = load_config()
    bus = EventBus()
    detector = USBDetector(bus)
    bus.subscribe("usb_inserted", lambda e: on_usb_inserted(e, config))
    print("Semper USB running. Waiting for USB insertion...")
    detector.start()
    detector._thread.join()   # Block main thread


if __name__ == "__main__":
    main()
```

**Step 2: Run the full test suite**

```bash
pytest tests/ -v
```
Expected: All existing tests PASS

**Step 3: Commit**

```bash
git add main.py
git commit -m "feat: wire full pipeline in main.py with daemon loop, GUI, and event bus"
```

---

## Task 13: Integration Test with EICAR

**Files:**
- Create: `tests/test_integration.py`
- Create: `tests/fixtures/eicar.txt`

**Step 1: Create EICAR test file**

The EICAR test string is a universally recognized anti-malware test file — safe, not actual malware:

```
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```

Write this exact string (no newline) to `tests/fixtures/eicar.txt`.

**Step 2: Write integration test**

```python
# tests/test_integration.py
"""
Integration test — runs the full pipeline (minus write-blocker) against a fixture directory.
Requires ClamAV to be running locally.
"""
import pytest
from pathlib import Path
from datetime import datetime
from unittest.mock import patch, MagicMock

from core.pipeline import PipelineContext
from core.events import EventBus
from core.orchestrator import Orchestrator
from stages.scanner import Scanner
from stages.triage import TriageEngine
from stages.copier import ForensicCopier
from stages.sorter import Sorter
from stages.packager import Packager


FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.integration
def test_full_pipeline_flags_eicar(tmp_path, sample_config):
    """Runs scanner through packager against EICAR test file."""
    out = tmp_path / "output"
    out.mkdir()

    ctx = PipelineContext(scan_start_time=datetime.now(), mode="C")
    ctx.usb_path = str(FIXTURES)
    ctx.mount_point = str(FIXTURES)
    ctx.usb_label = "TEST_USB"
    ctx.usb_serial = "SERIAL000"
    ctx.output_dir = str(out)

    sample_config["yara_rules_dir"] = "rules/yara"
    bus = EventBus()
    stages = [Scanner(sample_config), TriageEngine(), ForensicCopier(), Sorter(), Packager(sample_config)]
    orch = Orchestrator(stages, bus)
    ctx = orch.run(ctx)

    assert len(ctx.flagged_files) >= 1
    assert ctx.zip_path
    assert Path(ctx.zip_path).exists()
```

**Step 3: Run integration test (requires ClamAV running)**

```bash
pytest tests/test_integration.py -v -m integration
```
Expected: 1 PASSED (if ClamAV is running and has EICAR signature)

**Step 4: Commit**

```bash
git add tests/test_integration.py tests/fixtures/eicar.txt
git commit -m "test: add EICAR integration test for full pipeline"
```

---

## Task 14: GitHub Actions CI

**Files:**
- Create: `.github/workflows/ci.yml`

**Step 1: Create CI workflow**

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test-linux:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - name: Install ClamAV
        run: |
          sudo apt-get update
          sudo apt-get install -y clamav clamav-daemon
          sudo freshclam
          sudo service clamav-daemon start
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Run unit tests
        run: pytest tests/ -v --ignore=tests/test_integration.py -m "not integration"
      - name: Run integration tests
        run: pytest tests/test_integration.py -v -m integration

  test-windows:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Run unit tests (no ClamAV on Windows runner)
        run: pytest tests/ -v --ignore=tests/test_integration.py --ignore=tests/test_write_blocker.py -m "not integration"
```

**Step 2: Commit and push**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add GitHub Actions matrix for Linux and Windows unit + integration tests"
GIT_SSH_COMMAND="ssh -i ~/.ssh/github_key" git push origin main
```

**Step 3: Verify CI passes**

Go to `github.com/ftacorn/semper-usb/actions` and confirm both jobs are green.

---

## Task 15: README

**Files:**
- Create: `README.md`

**Step 1: Create README.md**

```markdown
# Semper USB

Cross-platform USB malware scanner for host and malware analysts.

Automatically detects USB insertion, mounts the drive **read-only** (write-blocked),
scans for malicious content, forensically copies flagged files to the host,
sorts by threat category, and packages everything into a zip archive with a metadata report.

## Features

- Write-blocking before any scanning (OS-level)
- ClamAV + YARA + optional VirusTotal detection
- Threat triage: ransomware > exploit > malware > suspicious_scripts > pua
- Forensic copy with timestamp preservation
- Sorted output: `/category/signature/filename`
- C-mode: zip + report.json + directory_tree.txt
- D-mode: adds chain of custody, volume manifest, integrity hash
- tkinter GUI: confirm dialog, per-stage progress bar, summary

## Requirements

- Python 3.11+
- ClamAV (`clamd` running)
- Optional: VirusTotal API key

## Setup

```bash
pip install -r requirements.txt
cp config.yaml.example config.yaml   # edit API keys, output dir
python main.py
```

## Running Tests

```bash
pytest tests/ -v                     # unit tests
pytest tests/ -v -m integration      # requires ClamAV running
```

## Output Structure

```
output/YYYY-MM-DD_HHMMSS_LABEL/
├── ransomware/Win.Ransomware.WannaCry/evil.exe
├── suspicious_scripts/Obfuscated_PowerShell/run.ps1
├── directory_tree.txt
├── report.json
└── semper_usb_package.zip
```

## D-mode (Forensic Grade)

Set `mode: D` in `config.yaml` or run with `--forensic`.
Adds chain of custody log, SHA256 volume manifest, and integrity signature to the zip.
```

**Step 2: Commit and push**

```bash
git add README.md
git commit -m "docs: add README with setup, usage, and output structure"
GIT_SSH_COMMAND="ssh -i ~/.ssh/github_key" git push origin main
```

---

## Final Verification Checklist

- [ ] `pytest tests/ -v` — all unit tests pass
- [ ] `pytest tests/ -v -m integration` — EICAR detected and flagged
- [ ] GUI smoke test — confirm dialog and overlay appear correctly
- [ ] CI green on `github.com/ftacorn/semper-usb/actions`
- [ ] Output zip contains report.json, sorted files, directory_tree.txt
- [ ] D-mode zip contains chain_of_custody.txt and volume_manifest.sha256
