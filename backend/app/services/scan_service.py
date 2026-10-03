"""Scan orchestration service. Wraps the scanner modules for use by the API."""

from pathlib import Path

from backend.app.models.findings import ScanResult
from backend.app.scanner.file_scanner import scan_directory

# Path to the demo vulnerable app — relative to project root
DEMO_APP_PATH = Path(__file__).parent.parent.parent.parent / "demo_vulnerable_app"


def run_demo_scan() -> ScanResult:
    """Run the PII scanner on the demo vulnerable app. Returns internal ScanResult."""
    result = scan_directory(str(DEMO_APP_PATH))
    return result


def run_upload_scan(extracted_dir: str) -> ScanResult:
    """Run the PII scanner on an extracted upload directory."""
    result = scan_directory(extracted_dir)
    return result
