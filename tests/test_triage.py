# tests/test_triage.py
from stages.triage import TriageEngine, CATEGORY_PRIORITY
from core.pipeline import PipelineContext, FlaggedFile, ScannedFile
from datetime import datetime


def make_flagged(signatures: list[str], engines: list[str]) -> FlaggedFile:
    return FlaggedFile(
        path="/usb/evil.exe",
        sha256="abc123",
        md5="def456",
        size_bytes=1024,
        engines=engines,
        signatures=signatures,
    )


def make_ctx(flagged: list[FlaggedFile]) -> PipelineContext:
    ctx = PipelineContext(scan_start_time=datetime.now(), mode="C")
    ctx.flagged_files = flagged
    return ctx


def test_ransomware_takes_priority_over_pua():
    ctx = make_ctx([make_flagged(["Win.Ransomware.WannaCry", "Win.PUA.Adware"], ["clamav"])])
    triage = TriageEngine()
    ctx = triage.run(ctx)
    assert ctx.flagged_files[0].category == "ransomware"


def test_exploit_beats_malware():
    ctx = make_ctx([make_flagged(["CVE-2021-40444", "Win.Trojan.Generic"], ["clamav"])])
    triage = TriageEngine()
    ctx = triage.run(ctx)
    assert ctx.flagged_files[0].category == "exploit"


def test_unknown_flagged_catch_all():
    ctx = make_ctx([make_flagged(["unrecognized.sig.xyz"], ["virustotal"])])
    triage = TriageEngine()
    ctx = triage.run(ctx)
    assert ctx.flagged_files[0].category == "unknown_flagged"


def test_categorized_dict_built():
    flagged = [
        make_flagged(["Win.Ransomware.Locky"], ["clamav"]),
        make_flagged(["Obfuscated_PowerShell"], ["yara"]),
    ]
    ctx = make_ctx(flagged)
    triage = TriageEngine()
    ctx = triage.run(ctx)
    assert "ransomware" in ctx.categorized
    assert "suspicious_scripts" in ctx.categorized
