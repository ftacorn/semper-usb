# Semper USB

Cross-platform USB malware scanner for host and malware analysts.

Automatically detects USB insertion, mounts the drive **read-only** (write-blocked), scans for malicious content, forensically copies flagged files to the host, sorts by threat category, and packages everything into a zip archive with a metadata report.

## Features

- Write-blocking before any scanning (OS-level read-only mount)
- ClamAV + YARA + optional VirusTotal detection
- Threat triage: `ransomware` > `exploit` > `malware` > `suspicious_scripts` > `pua`
- Forensic copy with timestamp preservation
- Sorted output: `/category/signature/filename`
- **C-mode** (default): zip + `report.json` + `directory_tree.txt`
- **D-mode** (forensic-grade): adds chain of custody, volume manifest, integrity hash
- tkinter GUI: confirm dialog, per-stage progress bar, scan summary

## Requirements

- Python 3.11+
- ClamAV with `clamd` daemon running
- Linux: `pyudev`, `mount` (root/sudo for write-blocking)
- Windows: `wmi`, admin privileges for registry write-block
- Optional: VirusTotal API key

## Setup

```bash
git clone git@github.com:ftacorn/semper-usb.git
cd semper-usb
pip install -r requirements.txt
cp config.yaml config.yaml.bak  # optional backup
# Edit config.yaml: set output_dir, analyst_name, virustotal.api_key if needed
python main.py
```

## Configuration

Edit `config.yaml`:

| Key | Default | Description |
|---|---|---|
| `output_dir` | `~/semper-usb/output` | Where flagged file packages are saved |
| `mode` | `C` | `C` = standard, `D` = forensic-grade |
| `analyst_name` | `""` | Used in D-mode chain of custody |
| `yara_rules_dir` | `rules/yara` | Drop `.yar`/`.yara` files here |
| `virustotal.enabled` | `false` | Enable VirusTotal hash lookup |
| `virustotal.api_key` | `""` | Your VT API key |
| `virustotal.upload_files` | `false` | Upload files (vs. hash-only lookup) |
| `virustotal.min_detections` | `3` | Minimum VT engine hits to flag |

## Running Tests

```bash
# Unit tests (no external dependencies)
pytest tests/ -v -m "not integration"

# Integration tests (requires ClamAV daemon running)
pytest tests/test_integration.py -v -m integration
```

## Output Structure

```
output/YYYY-MM-DD_HHMMSS_LABEL/
├── ransomware/
│   └── Win.Ransomware.WannaCry/
│       └── evil.exe
├── suspicious_scripts/
│   └── Obfuscated_PowerShell/
│       └── run_me.ps1
├── directory_tree.txt       # full USB file listing (clean + flagged)
├── report.json              # per-file metadata
└── semper_usb_package.zip   # everything zipped
```

## D-mode (Forensic-Grade)

Set `mode: D` in `config.yaml`. Adds to the zip:

| Artifact | Purpose |
|---|---|
| `chain_of_custody.txt` | Analyst name, scan time, USB serial, tool version |
| `volume_manifest.sha256` | SHA256 of every file on the USB |

Hashing occurs on the **read-only mount** before any copying — preserving forensic integrity.

## Adding YARA Rules

Drop `.yar` or `.yara` files into `rules/yara/`. They are compiled and run automatically on every scan. Rule names become part of the sorted output directory structure.

## Architecture

Modular pipeline — each stage is independently testable:

```
[USB Detector] → [Write Blocker] → [Scanner] → [Triage] → [Copier] → [Sorter] → [Packager]
                                                         ↑
                                     GUI Overlay (event subscriber, always-on)
```

## License

MIT
