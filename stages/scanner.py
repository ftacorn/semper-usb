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

        for filepath in all_files:
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
