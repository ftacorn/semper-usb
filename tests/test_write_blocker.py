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
