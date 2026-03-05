import pytest


@pytest.fixture
def tmp_output(tmp_path):
    """Temporary output directory for each test."""
    return tmp_path / "output"


@pytest.fixture
def sample_config(tmp_path):
    return {
        "output_dir": str(tmp_path / "semper-test"),
        "mode": "C",
        "virustotal": {"enabled": False, "api_key": "", "upload_files": False},
        "yara_rules_dir": "rules/yara",
        "analyst_name": "Test Analyst",
        "clamav": {"socket": "/var/run/clamav/clamd.ctl", "host": "127.0.0.1", "port": 3310},
    }
