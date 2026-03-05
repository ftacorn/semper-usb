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
