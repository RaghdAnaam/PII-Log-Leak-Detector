import sys
import uuid

from backend.app.detectors.email_detector import EmailDetector
from backend.app.detectors.phone_detector import PhoneDetector
from backend.app.detectors.ic_detector import ICDetector
from backend.app.detectors.credit_card_detector import CreditCardDetector
from backend.app.detectors.account_number_detector import AccountNumberDetector
from backend.app.models.findings import Finding, Severity, ScanResult

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
    """Scan a single log file for PII findings. Every line is treated as log output."""
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
