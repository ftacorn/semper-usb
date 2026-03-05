# Semper USB — Design Document
**Date:** 2026-03-05
**Status:** Approved

---

## Overview

Semper USB is a cross-platform (Windows/Linux) Python tool that automatically detects USB drive insertion, mounts the drive read-only (write-blocked), scans all files for malicious or suspicious content, forensically copies flagged files to the host, sorts them by threat category, and packages the results into a zip archive with a metadata report.

Target users: host analysts and malware analysts.

---

## Architecture

Modular pipeline architecture. A core orchestrator iterates discrete, swappable stages in order. Each stage implements a common `PipelineStage` interface and receives/returns a shared `PipelineContext` dataclass. A pub/sub event bus decouples the GUI from the pipeline entirely.

```
[USB Detector] → [Write Blocker] → [Scanner] → [Triage Engine] → [Copier] → [Sorter] → [Packager]
                                                                                              ↑
                                                           GUI Overlay (event subscriber, always-on)
```

---

## Project Structure

```
semper-usb/
├── main.py                  # Entry point — starts daemon + GUI event loop
├── config.yaml              # User config: output dir, VirusTotal API key, YARA rules path, D-mode toggle
├── requirements.txt
├── README.md
│
├── core/
│   ├── orchestrator.py      # Iterates pipeline stages, emits progress events
│   ├── pipeline.py          # PipelineStage base class + PipelineContext dataclass
│   └── events.py            # Simple pub/sub event bus (stage_start, progress, stage_done, error)
│
├── stages/
│   ├── detector.py          # USB insertion detection (udev / WMI)
│   ├── write_blocker.py     # OS-level read-only enforcement
│   ├── scanner.py           # ClamAV + YARA + optional VirusTotal
│   ├── triage.py            # Maps detections to threat categories
│   ├── copier.py            # Forensic file copy (read-only handles, timestamp preservation)
│   ├── sorter.py            # Builds /category/signature/ directory tree
│   └── packager.py          # C-mode zip + report; D-mode adds COC log + manifest
│
├── gui/
│   ├── overlay.py           # tkinter window — progress bar, stage breadcrumbs, summary
│   └── confirm_dialog.py    # Initial "USB detected — scan now?" prompt
│
├── rules/
│   └── yara/                # Analyst-supplied YARA rule files (.yar)
│
└── docs/
    └── plans/
        └── 2026-03-05-semper-usb-design.md
```

---

## Data Flow — PipelineContext

The `PipelineContext` dataclass is the single object passed between every stage:

```python
@dataclass
class PipelineContext:
    # Set by detector
    usb_path: str
    usb_label: str
    usb_serial: str
    mount_point: str

    # Set by scanner
    scanned_files: list[ScannedFile]
    flagged_files: list[FlaggedFile]

    # Set by triage
    categorized: dict[str, list]

    # Set by copier/sorter
    output_dir: str
    directory_tree: str

    # Set by packager
    zip_path: str
    report: ScanReport

    # Runtime
    scan_start_time: datetime
    mode: Literal["C", "D"]
    errors: list[str]
```

Each `FlaggedFile` carries: original path, SHA256 + MD5 hash (computed on read-only mount before copy), detection engine(s), signature/rule name(s), threat category, and original timestamps.

---

## Scanner & Triage Logic

### Scanning (layered, in order)

1. **ClamAV** — offline, known signature detection via clamd socket
2. **YARA** — rule-based pattern matching via yara-python, using rules from `rules/yara/`
3. **VirusTotal** (optional) — SHA256 hash lookup by default; full file upload as opt-in

A file is flagged if any engine finds a match. All matches are recorded.

### Threat Category Priority (worst wins)

| Priority | Category | Example Signatures |
|---|---|---|
| 1 | `ransomware` | `Win.Ransomware.*`, YARA `encrypt_file_extensions` |
| 2 | `exploit` | `CVE-*`, `Exploit.*`, YARA `shellcode_*` |
| 3 | `malware` | `Win.Trojan.*`, `Linux.Backdoor.*` |
| 4 | `suspicious_scripts` | YARA `obfuscated_powershell`, `base64_vbs` |
| 5 | `pua` | `Win.PUA.*`, `Adware.*` |
| 6 | `unknown_flagged` | VirusTotal >3/70, no category match |

### Output Directory Structure

```
output/
└── YYYY-MM-DD_HHMMSS_<usb_label>/
    ├── ransomware/
    │   └── Win.Ransomware.WannaCry/
    │       └── evil.exe
    ├── suspicious_scripts/
    │   └── obfuscated_powershell/
    │       └── run_me.ps1
    ├── directory_tree.txt
    ├── report.json
    └── semper_usb_package.zip
```

---

## GUI Overlay

Built with `tkinter` (stdlib). Three sequential windows:

### 1. Confirm Dialog
Shown on USB insertion. Displays USB label, serial, and path. Analyst clicks "Scan Now" or "Ignore".

### 2. Scan Progress Overlay
Persistent window showing:
- Current stage name and description
- Per-stage progress bar (files processed / total)
- Stage breadcrumb row (checkmark = done, arrow = active, circle = pending)
- Elapsed time

GUI runs on a separate thread. Orchestrator pushes events to a thread-safe `queue.Queue`. GUI polls via `root.after(100, poll_queue)`.

### 3. Summary Window
Shown on completion. Displays file count, threat count by category, output path. Buttons: "Open Output Folder" and "Dismiss".

---

## Packager Modes

### C-mode (default)
- Flagged files in sorted directory structure
- `directory_tree.txt` — full USB file listing (flagged + clean)
- `report.json` — per-file metadata (path, hashes, engine, category, timestamps)
- All zipped into `semper_usb_package.zip`

### D-mode (opt-in via `config.yaml` or `--forensic` flag)
Adds to C-mode:
- `chain_of_custody.txt` — analyst name, date/time, USB serial, tool version, zip hash
- `volume_manifest.sha256` — SHA256 of every file on the USB
- `integrity.sig` — hash of the final zip file

---

## Error Handling

| Scenario | Behavior |
|---|---|
| ClamAV not installed | Skip stage, log warning in report, continue |
| VirusTotal rate limit | Mark files as `vt_skipped`, continue |
| File unreadable on USB | Log to `errors[]`, skip file, continue |
| Write-block fails | **Hard abort** — alert analyst, do not proceed |
| USB removed mid-scan | Catch IO error, abort cleanly, write partial report |

Write-block failure is the only hard abort. All other failures degrade gracefully.

---

## Testing Strategy

- **Unit tests** — each stage tested in isolation with mock `PipelineContext`
- **Integration test** — full pipeline run against a test USB image (`.img`) with planted EICAR files
- **GUI** — manual smoke test checklist
- **Platform matrix** — CI via GitHub Actions on Ubuntu + Windows runners

---

## Stack

| Component | Technology |
|---|---|
| Language | Python 3.11+ |
| USB detection | `pyudev` (Linux), `wmi` (Windows) |
| Write blocking | `udev` ro mount (Linux), registry `WriteProtect` (Windows) |
| ClamAV | `clamd` Python binding |
| YARA | `yara-python` |
| VirusTotal | `vt-py` |
| GUI | `tkinter` (stdlib) |
| Packaging | `zipfile` (stdlib) |
| Config | `PyYAML` |

---

## GitHub

Repository: `github.com/ftacorn/semper-usb`
SSH key: `~/.ssh/github_key`
