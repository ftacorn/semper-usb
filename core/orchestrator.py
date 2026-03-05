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
