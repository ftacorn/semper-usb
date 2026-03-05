# tests/test_orchestrator.py
from core.orchestrator import Orchestrator, AbortPipeline
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
