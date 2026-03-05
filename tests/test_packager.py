# tests/test_packager.py
import json, zipfile
from stages.packager import Packager
from core.pipeline import PipelineContext, FlaggedFile, ScanReport, ScannedFile
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
    ctx.scanned_files = [ScannedFile(path="/usb/evil.exe", sha256="abc123", md5="def456", size_bytes=3)]
    ctx.categorized = {"malware": ctx.flagged_files}
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
