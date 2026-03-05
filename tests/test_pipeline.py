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
