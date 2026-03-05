import pytest
from pathlib import Path
import tempfile, shutil


@pytest.fixture
def tmp_output(tmp_path):
    """Temporary output directory for each test."""
    return tmp_path / "output"


@pytest.fixture
def sample_config():
    return {
        "output_dir": "/tmp/semper-test",
        "mode": "C",
        "virustotal": {"enabled": False, "api_key": "", "upload_files": False},
        "yara_rules_dir": "rules/yara",
        "analyst_name": "Test Analyst",
        "clamav": {"socket": "/var/run/clamav/clamd.ctl", "host": "127.0.0.1", "port": 3310},
    }
