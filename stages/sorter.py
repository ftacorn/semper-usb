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
                else:
                    ctx.errors.append(f"Sort skipped for {f.path}: file not found at source or output staging area")
            except Exception as e:
                ctx.errors.append(f"Sort failed for {f.path}: {e}")

        return ctx
