# Semper USB — Deployment Guide

## Table of Contents

- [Linux (Ubuntu/Debian)](#linux-ubuntudebian)
- [Windows](#windows)
- [Configuration Reference](#configuration-reference)
- [Running Semper USB](#running-semper-usb)
- [D-mode (Forensic-Grade)](#d-mode-forensic-grade)
- [Adding YARA Rules](#adding-yara-rules)
- [Troubleshooting](#troubleshooting)

---

## Linux (Ubuntu/Debian)

### 1. Install system dependencies

```bash
sudo apt-get update
sudo apt-get install -y clamav clamav-daemon clamav-data python3 python3-pip
```

### 2. Initialize the ClamAV database

The ClamAV daemon will not start without a current virus database. Run `freshclam` once to download it:

```bash
sudo systemctl stop clamav-freshclam   # stop the update service temporarily
sudo freshclam                          # download the database (~300 MB)
sudo systemctl start clamav-freshclam  # re-enable automatic updates
```

### 3. Start and enable the ClamAV daemon

```bash
sudo systemctl enable clamav-daemon
sudo systemctl start clamav-daemon

# Verify it is running
sudo systemctl status clamav-daemon
```

### 4. Clone and install Semper USB

```bash
git clone git@github.com:ftacorn/semper-usb.git
cd semper-usb
pip install -r requirements.txt
```

### 5. Configure

```bash
# Edit config.yaml — set output_dir and analyst_name at minimum
nano config.yaml
```

### 6. Run

Semper USB needs root to write-block the USB drive at the OS level:

```bash
sudo python3 main.py
```

---

## Windows

### 1. Install Python

Download and install Python 3.11+ from [python.org](https://www.python.org/downloads/). During installation, check **"Add Python to PATH"**.

### 2. Install ClamAV

1. Download the ClamAV Windows installer from [clamav.net](https://www.clamav.net/downloads)
2. Run the installer (default path: `C:\Program Files\ClamAV\`)
3. Copy the sample config files:
   ```
   copy "C:\Program Files\ClamAV\conf_examples\clamd.conf.sample" "C:\Program Files\ClamAV\clamd.conf"
   copy "C:\Program Files\ClamAV\conf_examples\freshclam.conf.sample" "C:\Program Files\ClamAV\freshclam.conf"
   ```
4. Open both files and remove or comment out the `Example` line at the top
5. Download the virus database:
   ```
   "C:\Program Files\ClamAV\freshclam.exe"
   ```
6. Start the ClamAV service:
   ```
   "C:\Program Files\ClamAV\clamd.exe"
   ```

### 3. Clone and install Semper USB

```powershell
git clone git@github.com:ftacorn/semper-usb.git
cd semper-usb
pip install -r requirements.txt
```

### 4. Configure

Open `config.yaml` and update the ClamAV section for TCP mode (Windows does not use a Unix socket):

```yaml
clamav:
  host: 127.0.0.1
  port: 3310
```

### 5. Run

Semper USB needs Administrator privileges to write-block via the Windows registry. Right-click your terminal and select **"Run as Administrator"**, then:

```powershell
python main.py
```

---

## Configuration Reference

All settings live in `config.yaml` in the project root.

| Key | Default | Description |
|---|---|---|
| `output_dir` | `~/semper-usb/output` | Directory where scan packages are saved |
| `mode` | `C` | `C` = standard output, `D` = forensic-grade (see below) |
| `analyst_name` | `""` | Written into the D-mode chain of custody log |
| `yara_rules_dir` | `rules/yara` | Directory containing `.yar` / `.yara` rule files |
| `clamav.socket` | `/var/run/clamav/clamd.ctl` | Unix socket path (Linux) |
| `clamav.host` | `127.0.0.1` | ClamAV TCP host (Windows or remote daemon) |
| `clamav.port` | `3310` | ClamAV TCP port |
| `virustotal.enabled` | `false` | Enable VirusTotal hash lookups |
| `virustotal.api_key` | `""` | Your VirusTotal API key |
| `virustotal.upload_files` | `false` | Upload files to VT (vs. hash-only lookup) |
| `virustotal.min_detections` | `3` | Minimum VT engine hits required to flag a file |

**Minimal working config:**

```yaml
output_dir: /home/analyst/usb-scans
mode: C
analyst_name: "Jane Smith"

clamav:
  socket: /var/run/clamav/clamd.ctl
  host: 127.0.0.1
  port: 3310

yara_rules_dir: rules/yara

virustotal:
  enabled: false
  api_key: ""
  upload_files: false
  min_detections: 3
```

---

## Running Semper USB

```bash
sudo python3 main.py          # Linux (root required for write-blocking)
python main.py                # Windows (run terminal as Administrator)
```

On startup, Semper USB enters daemon mode and waits for a USB drive to be inserted. When one is detected:

1. A confirmation dialog appears showing the USB label, serial number, and device path
2. Click **Scan Now** to proceed or **Ignore** to dismiss
3. The scan overlay appears, showing live progress through each stage:
   - Write Blocker → Scanner → Triage → Copier → Sorter → Packager
4. On completion, a summary window shows threat counts by category and the output path

Results are saved to `output_dir` as a timestamped folder:

```
output/
└── 2026-03-05_143022_MY_USB/
    ├── ransomware/
    │   └── Win.Ransomware.WannaCry/
    │       └── evil.exe
    ├── malware/
    │   └── Win.Trojan.Agent/
    │       └── payload.dll
    ├── directory_tree.txt          # full listing of every file on the USB
    ├── report.json                 # per-file metadata (path, hashes, engine, category)
    └── semper_usb_package.zip      # everything above in a single archive
```

---

## D-mode (Forensic-Grade)

Set `mode: D` in `config.yaml` to enable forensic-grade output. D-mode produces everything C-mode does, plus:

| Artifact | Purpose |
|---|---|
| `chain_of_custody.txt` | Analyst name, scan start time, USB label and serial, tool version |
| `volume_manifest.sha256` | SHA256 hash of every file on the USB drive |
| `integrity.sig` | SHA256 hash of the final zip archive |

All hashing is performed on the **read-only mount** before any files are copied, preserving forensic integrity of the original media.

---

## Adding YARA Rules

Drop `.yar` or `.yara` rule files into the `rules/yara/` directory. They are compiled and applied automatically on every scan — no restart required.

Rule names from YARA matches are used as the subdirectory name inside the threat category folder in the output (e.g., `suspicious_scripts/obfuscated_powershell/run_me.ps1`).

**Example rule file** (`rules/yara/scripts.yar`):

```yara
rule obfuscated_powershell
{
    strings:
        $enc = "FromBase64String" nocase
        $cmd = "IEX" nocase
    condition:
        all of them
}
```

---

## Troubleshooting

### ClamAV daemon is not running

```bash
# Check status
sudo systemctl status clamav-daemon

# If it shows "condition not met" or "skipped", the database is missing
sudo freshclam
sudo systemctl start clamav-daemon
```

### Write-block fails on Linux

Semper USB aborts if the USB cannot be mounted read-only — this is intentional. Check that:
- You are running as root (`sudo python3 main.py`)
- The device path is correct (check `lsblk` or `dmesg | tail`)
- The device is not already mounted elsewhere (`umount /dev/sdX` first)

### Write-block fails on Windows

- Ensure the terminal is running as Administrator
- The registry key `HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies\WriteProtect` must be writable

### No GUI appears (headless environment)

If running in a headless environment (SSH session, server), tkinter will fail to open a window. The pipeline will still run — it auto-approves the confirmation prompt and skips the overlay when no display is available.

### VirusTotal lookups are slow or failing

- Free VT API keys are rate-limited to 4 requests/minute. Large USB drives may hit the limit — files that exceed the limit are marked `vt_skipped` in the report and scanning continues.
- Set `virustotal.enabled: false` to disable VT entirely if not needed.
