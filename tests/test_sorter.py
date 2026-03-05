# tests/test_sorter.py
from stages.sorter import Sorter
from core.pipeline import PipelineContext, FlaggedFile
from datetime import datetime
from pathlib import Path


def make_flagged(path, category, signature):
    return FlaggedFile(
        path=path, sha256="x", md5="y", size_bytes=10,
        category=category, signatures=[signature], engines=["clamav"],
    )


def test_sorter_creates_category_subdirs(tmp_path):
    out = tmp_path / "output"
    out.mkdir()
    src = tmp_path / "src"
    src.mkdir()
    evil = src / "evil.exe"
    evil.write_bytes(b"BAD")

    ctx = PipelineContext(scan_start_time=datetime.now(), mode="C")
    ctx.output_dir = str(out)
    ctx.flagged_files = [make_flagged(str(evil), "malware", "Win.Trojan.Generic")]
    ctx.categorized = {"malware": ctx.flagged_files}

    # Copy the file to output first (mimicking what copier does)
    import shutil
    shutil.copy2(str(evil), str(out / "evil.exe"))

    sorter = Sorter()
    ctx = sorter.run(ctx)

    expected = out / "malware" / "Win.Trojan.Generic"
    assert expected.is_dir()
    assert (expected / "evil.exe").exists()
