"""
Log file scanner — scans application log files for PII.

Unlike the file scanner (which inspects source code), every line here is
treated as live log output. There is no context-window enrichment — the
detection reason is set uniformly to indicate the PII was found in a log file,
which is inherently an exposure event.

Entry point:
- :func:`scan_log_file` — scan a single ``.log`` (or any text) file.
"""

import sys
import uuid

from backend.app.detectors.account_number_detector import AccountNumberDetector
from backend.app.detectors.credit_card_detector import CreditCardDetector
from backend.app.detectors.email_detector import EmailDetector
from backend.app.detectors.ic_detector import ICDetector
from backend.app.detectors.phone_detector import PhoneDetector
from backend.app.models.findings import Finding, ScanResult, Severity

# Instantiate detectors once at module level
_DETECTORS = [
    EmailDetector(),
    PhoneDetector(),
    ICDetector(),
    CreditCardDetector(),
    AccountNumberDetector(),
]

_LOG_DETECTION_REASON = (
    "Found in application log file. Potential PII exposure in log output."
)


def scan_log_file(path: str) -> ScanResult:
    """Scan a single log file for PII findings.

    Every line is treated as live log output. All findings receive the same
    ``detection_reason`` string indicating they were found in an application
    log, regardless of which detector triggered.

    Reads the file as UTF-8. Skips silently (with a stderr warning) if the
    file cannot be decoded or does not exist.

    Args:
        path: Absolute or relative path to the log file.

    Returns:
        A :class:`ScanResult` with all findings, per-severity counts, and a
        fresh UUID ``scan_id``. ``files_scanned`` is always 1. Returns a
        zero-finding result if the file is empty, unreadable, or clean.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except UnicodeDecodeError:
        print(f"Warning: could not decode {path} as UTF-8, skipping.", file=sys.stderr)
        lines = []
    except FileNotFoundError:
        print(f"Warning: file not found: {path}", file=sys.stderr)
        lines = []

    all_findings: list[Finding] = []

    for line_idx, line in enumerate(lines):
        line_number = line_idx + 1  # 1-based
        for detector in _DETECTORS:
            for finding in detector.detect(text=line, file=path, line_offset=line_number):
                finding.detection_reason = _LOG_DETECTION_REASON
                all_findings.append(finding)

    high_count = sum(1 for f in all_findings if f.severity == Severity.HIGH)
    medium_count = sum(1 for f in all_findings if f.severity == Severity.MEDIUM)
    low_count = sum(1 for f in all_findings if f.severity == Severity.LOW)

    return ScanResult(
        scan_id=str(uuid.uuid4()),
        files_scanned=1,
        total_findings=len(all_findings),
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        findings=all_findings,
    )
