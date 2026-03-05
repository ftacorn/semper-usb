# tests/test_copier.py
from stages.copier import ForensicCopier
from core.pipeline import PipelineContext, FlaggedFile, ScannedFile
from datetime import datetime
from pathlib import Path


def make_ctx(flagged, mount, output):
    ctx = PipelineContext(scan_start_time=datetime.now(), mode="C")
    ctx.flagged_files = flagged
    ctx.mount_point = str(mount)
    ctx.output_dir = str(output)
    return ctx


def test_copier_copies_flagged_files(tmp_path):
    # Create a fake USB file
    usb = tmp_path / "usb"
    usb.mkdir()
    evil = usb / "evil.exe"
    evil.write_bytes(b"EVIL")

    out = tmp_path / "output"
    out.mkdir()

    flagged = [FlaggedFile(
        path=str(evil), sha256="abc", md5="def",
        size_bytes=4, category="malware",
        signatures=["Win.Trojan.Generic"],
        engines=["clamav"],
    )]

    ctx = make_ctx(flagged, usb, out)
    copier = ForensicCopier()
    ctx = copier.run(ctx)

    # File should exist somewhere under output
    copied = list(out.rglob("evil.exe"))
    assert len(copied) == 1


def test_copier_builds_directory_tree(tmp_path):
    usb = tmp_path / "usb"
    usb.mkdir()
    (usb / "readme.txt").write_text("hello")
    (usb / "evil.exe").write_bytes(b"bad")

    out = tmp_path / "output"
    out.mkdir()

    ctx = make_ctx([], usb, out)
    copier = ForensicCopier()
    ctx = copier.run(ctx)

    assert "readme.txt" in ctx.directory_tree
    assert "evil.exe" in ctx.directory_tree
