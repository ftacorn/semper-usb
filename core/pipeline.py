"""Core pipeline primitives."""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal


@dataclass
class ScannedFile:
    path: str
    sha256: str
    md5: str
    size_bytes: int


@dataclass
class FlaggedFile(ScannedFile):
    engines: list[str] = field(default_factory=list)        # e.g. ["clamav", "yara"]
    signatures: list[str] = field(default_factory=list)     # e.g. ["Win.Ransomware.WannaCry"]
    category: str = ""                                       # assigned by triage
    original_timestamps: dict = field(default_factory=dict) # {created, modified, accessed}


@dataclass
class ScanReport:
    usb_label: str = ""
    usb_serial: str = ""
    total_files: int = 0
    flagged_count: int = 0
    categories: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


@dataclass
class PipelineContext:
    scan_start_time: datetime
    mode: Literal["C", "D"]

    # Set by detector
    usb_path: str = ""
    usb_label: str = ""
    usb_serial: str = ""
    mount_point: str = ""

    # Set by scanner
    scanned_files: list[ScannedFile] = field(default_factory=list)
    flagged_files: list[FlaggedFile] = field(default_factory=list)

    # Set by triage
    categorized: dict[str, list] = field(default_factory=dict)

    # Set by copier/sorter
    output_dir: str = ""
    directory_tree: str = ""

    # Set by packager
    zip_path: str = ""
    report: ScanReport = field(default_factory=ScanReport)

    # Runtime
    errors: list[str] = field(default_factory=list)


class PipelineStage:
    def __init__(self, name: str):
        self.name = name

    def run(self, ctx: PipelineContext) -> PipelineContext:
        raise NotImplementedError(f"{self.__class__.__name__} must implement run()")
