# tests/test_scanner.py
from unittest.mock import MagicMock, patch
from stages.scanner import Scanner
from core.pipeline import PipelineContext
from datetime import datetime
import tempfile, os


def make_ctx(tmp_path: str) -> PipelineContext:
    ctx = PipelineContext(scan_start_time=datetime.now(), mode="C")
    ctx.mount_point = tmp_path
    return ctx


def test_scanner_flags_clamav_match(tmp_path, sample_config):
    # Write a dummy file
    f = tmp_path / "evil.exe"
    f.write_bytes(b"MZ" + b"\x00" * 100)

    ctx = make_ctx(str(tmp_path))

    with patch("stages.scanner.clamd") as mock_clamd:
        mock_sock = MagicMock()
        mock_clamd.ClamdUnixSocket.return_value = mock_sock
        mock_clamd.ClamdNetworkSocket.return_value = mock_sock
        mock_sock.ping.return_value = True
        mock_sock.scan.return_value = {
            str(f): ("FOUND", "Win.Trojan.Generic-1234")
        }
        scanner = Scanner(sample_config)
        ctx = scanner.run(ctx)

    assert len(ctx.flagged_files) == 1
    assert ctx.flagged_files[0].signatures == ["Win.Trojan.Generic-1234"]
    assert "clamav" in ctx.flagged_files[0].engines


def test_scanner_clean_file_not_flagged(tmp_path, sample_config):
    f = tmp_path / "clean.txt"
    f.write_text("hello world")

    ctx = make_ctx(str(tmp_path))

    with patch("stages.scanner.clamd") as mock_clamd:
        mock_sock = MagicMock()
        mock_clamd.ClamdUnixSocket.return_value = mock_sock
        mock_clamd.ClamdNetworkSocket.return_value = mock_sock
        mock_sock.ping.return_value = True
        mock_sock.scan.return_value = {str(f): ("OK", None)}
        scanner = Scanner(sample_config)
        ctx = scanner.run(ctx)

    assert len(ctx.flagged_files) == 0
    assert len(ctx.scanned_files) == 1


def test_scanner_clamav_unavailable_continues(tmp_path, sample_config):
    f = tmp_path / "file.txt"
    f.write_text("data")
    ctx = make_ctx(str(tmp_path))

    with patch("stages.scanner.clamd") as mock_clamd:
        mock_clamd.ClamdUnixSocket.side_effect = Exception("ClamAV not running")
        mock_clamd.ClamdNetworkSocket.side_effect = Exception("ClamAV not running")
        scanner = Scanner(sample_config)
        ctx = scanner.run(ctx)

    assert any("ClamAV" in e for e in ctx.errors)
    assert len(ctx.scanned_files) == 1   # still walked the files
