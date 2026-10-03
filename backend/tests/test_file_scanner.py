"""
Tests for file_scanner and log_scanner.
"""
import os
import tempfile
from pathlib import Path

from backend.app.scanner.file_scanner import scan_directory, scan_file

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_scan_vulnerable_file_line_numbers():
    """Test that findings have correct line numbers."""
    findings = scan_file(str(FIXTURES_DIR / "vulnerable_sample.py"))
    # Email should be on line 10: logger.info("User email: john.doe@example.com")
    email_findings = [f for f in findings if f.pii_type.value == "Email"]
    assert len(email_findings) >= 1, f"Expected at least 1 email finding, got {email_findings}"
    email_finding = email_findings[0]
    assert email_finding.line_number == 10, (
        f"Expected email on line 10, got line {email_finding.line_number}"
    )
    assert email_finding.line_number > 0


def test_scan_vulnerable_file_has_multiple_pii_types():
    """Vulnerable sample contains email, phone, IC, credit card, account."""
    findings = scan_file(str(FIXTURES_DIR / "vulnerable_sample.py"))
    pii_types = {f.pii_type.value for f in findings}
    assert "Email" in pii_types
    assert "Phone" in pii_types
    assert "Malaysian IC" in pii_types
    assert "Credit Card" in pii_types
    assert "Account Number" in pii_types


def test_scan_clean_file_zero_findings():
    """A PII-free file should produce zero findings."""
    findings = scan_file(str(FIXTURES_DIR / "clean_sample.py"))
    assert len(findings) == 0, (
        f"Expected 0 findings, got {len(findings)}: {[f.pii_type for f in findings]}"
    )


def test_scan_directory_ignores_pycache():
    """__pycache__ directories must be skipped."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Write a file with PII in __pycache__
        pycache = os.path.join(tmpdir, "__pycache__")
        os.makedirs(pycache)
        with open(os.path.join(pycache, "cached.py"), "w") as f:
            f.write('x = "john.doe@example.com"\n')

        # Write a normal file without PII
        with open(os.path.join(tmpdir, "clean.py"), "w") as f:
            f.write('x = 1\n')

        result = scan_directory(tmpdir)
        assert result.total_findings == 0, "__pycache__ should be ignored"


def test_scan_directory_ignores_fixed_dir():
    """_fixed/ directory must be skipped."""
    with tempfile.TemporaryDirectory() as tmpdir:
        fixed_dir = os.path.join(tmpdir, "_fixed")
        os.makedirs(fixed_dir)
        with open(os.path.join(fixed_dir, "safe.py"), "w") as f:
            f.write('x = "john.doe@example.com"\n')

        with open(os.path.join(tmpdir, "clean.py"), "w") as f:
            f.write('x = 1\n')

        result = scan_directory(tmpdir)
        assert result.total_findings == 0, "_fixed/ should be ignored"


def test_scan_directory_skips_binary_files():
    """Binary files should be silently skipped."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Write a binary file (with .py extension so it would be picked up if not binary-skipped)
        with open(os.path.join(tmpdir, "binary.py"), "wb") as f:
            f.write(b"\x00\x01\x02\x03")

        result = scan_directory(tmpdir)
        # Should not raise, should return 0 findings
        assert result.total_findings == 0


def test_scan_directory_metadata():
    """ScanResult should have correct metadata."""
    result = scan_directory(str(FIXTURES_DIR))
    assert result.files_scanned >= 1
    assert result.total_findings == result.high_count + result.medium_count + result.low_count
    assert result.scan_id != ""


def test_scan_file_returns_list():
    """scan_file always returns a list, even for missing files."""
    findings = scan_file("/nonexistent/path/file.py")
    assert isinstance(findings, list)
    assert len(findings) == 0


def test_scan_directory_nonexistent():
    """scan_directory returns empty ScanResult for missing directory."""
    result = scan_directory("/nonexistent/path/")
    assert result.total_findings == 0
    assert result.files_scanned == 0
