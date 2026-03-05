"""Triage Engine — maps detection signatures to threat categories."""
from __future__ import annotations
import re
from core.pipeline import PipelineContext, PipelineStage, FlaggedFile

# Priority order: index 0 = highest priority
CATEGORY_PRIORITY = [
    "ransomware",
    "exploit",
    "malware",
    "suspicious_scripts",
    "pua",
    "unknown_flagged",
]

# Patterns mapped to categories (checked in priority order)
SIGNATURE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("ransomware",        re.compile(r"ransomware|locker|cryptor", re.I)),
    ("exploit",           re.compile(r"CVE-\d{4}-\d+|exploit|shellcode", re.I)),
    ("malware",           re.compile(r"trojan|backdoor|rootkit|worm|virus|dropper", re.I)),
    ("suspicious_scripts",re.compile(r"obfuscat|powershell|base64.*vbs|vbs.*base64|macro", re.I)),
    ("pua",               re.compile(r"PUA|adware|riskware|unwanted", re.I)),
]


def _assign_category(signatures: list[str]) -> str:
    matched = set()
    for sig in signatures:
        for category, pattern in SIGNATURE_PATTERNS:
            if pattern.search(sig):
                matched.add(category)
    if not matched:
        return "unknown_flagged"
    # Return highest priority match
    for category in CATEGORY_PRIORITY:
        if category in matched:
            return category
    return "unknown_flagged"


class TriageEngine(PipelineStage):
    def __init__(self):
        super().__init__("Triage")

    def run(self, ctx: PipelineContext) -> PipelineContext:
        for f in ctx.flagged_files:
            f.category = _assign_category(f.signatures)

        ctx.categorized = {}
        for f in ctx.flagged_files:
            ctx.categorized.setdefault(f.category, []).append(f)

        return ctx
