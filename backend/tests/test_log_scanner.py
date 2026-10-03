"""
Tests for the log file scanner.
"""
from pathlib import Path

from backend.app.scanner.log_scanner import scan_log_file

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_scan_log_finds_pii():
    result = scan_log_file(str(FIXTURES_DIR / "sample.log"))
    assert result.total_findings >= 3
    assert result.files_scanned == 1


def test_scan_log_detects_email():
    result = scan_log_file(str(FIXTURES_DIR / "sample.log"))
    email_findings = [f for f in result.findings if f.pii_type.value == "Email"]
    assert len(email_findings) >= 1


def test_scan_log_detects_phone():
    result = scan_log_file(str(FIXTURES_DIR / "sample.log"))
    phone_findings = [f for f in result.findings if f.pii_type.value == "Phone"]
    assert len(phone_findings) >= 1


def test_scan_log_detects_ic():
    result = scan_log_file(str(FIXTURES_DIR / "sample.log"))
    ic_findings = [f for f in result.findings if f.pii_type.value == "Malaysian IC"]
    assert len(ic_findings) >= 1


def test_scan_log_detects_account():
    result = scan_log_file(str(FIXTURES_DIR / "sample.log"))
    account_findings = [f for f in result.findings if f.pii_type.value == "Account Number"]
    assert len(account_findings) >= 1


def test_scan_log_metadata():
    result = scan_log_file(str(FIXTURES_DIR / "sample.log"))
    assert result.scan_id != ""
    assert result.total_findings == result.high_count + result.medium_count + result.low_count


def test_scan_log_email_line_number():
    """Email is on line 4 of sample.log."""
    result = scan_log_file(str(FIXTURES_DIR / "sample.log"))
    email_findings = [f for f in result.findings if f.pii_type.value == "Email"]
    assert len(email_findings) >= 1
    assert email_findings[0].line_number == 4


def test_scan_log_missing_file():
    """Missing log file returns empty ScanResult, no exception."""
    result = scan_log_file("/nonexistent/path/app.log")
    assert result.total_findings == 0
    assert result.files_scanned == 1  # scanner still counts the attempted file


def test_scan_log_findings_have_masked_values():
    """All findings must have a masked_value that differs from matched_value."""
    result = scan_log_file(str(FIXTURES_DIR / "sample.log"))
    for finding in result.findings:
        assert finding.masked_value, "masked_value should not be empty"
        assert finding.matched_value != finding.masked_value, (
            f"masked_value should differ from matched_value for {finding.pii_type}"
        )
