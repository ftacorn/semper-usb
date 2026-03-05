"""
Integration test — runs the full pipeline (minus write-blocker) against a fixture directory.
Requires ClamAV daemon to be running locally.
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
