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
