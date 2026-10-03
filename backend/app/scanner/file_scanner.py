import os
import sys
import uuid

from backend.app.core.config import IGNORED_DIRS, SUPPORTED_EXTENSIONS
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

_CONTEXT_KEYWORDS = [
    "logger.info",
    "logger.warning",
    "logger.error",
    "logger.debug",
    "logger.exception",
    "print(",
    "raise",
    "except",
]


def scan_file(path: str) -> list[Finding]:
    """Scan a single file for PII findings."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except UnicodeDecodeError:
        print(f"Warning: could not decode {path} as UTF-8, skipping.", file=sys.stderr)
        return []
    except FileNotFoundError:
        print(f"Warning: file not found: {path}", file=sys.stderr)
        return []

    all_findings: list[Finding] = []

    for line_idx, line in enumerate(lines):
        line_number = line_idx + 1  # 1-based

        # Run all detectors on the current line
        line_findings: list[Finding] = []
        for detector in _DETECTORS:
            line_findings.extend(detector.detect(text=line, file=path, line_offset=line_number))

        if not line_findings:
            continue

        # Determine context window (±3 lines, excluding current line)
        context_start = max(0, line_idx - 3)
        context_end = min(len(lines), line_idx + 4)  # slice end is exclusive
        context_lines = lines[context_start:line_idx] + lines[line_idx + 1:context_end]
        context_text = "".join(context_lines)

        # Enrich detection_reason if a context keyword is found nearby
        nearby_keyword = None
        for keyword in _CONTEXT_KEYWORDS:
            if keyword in context_text:
                nearby_keyword = keyword
                break

        for finding in line_findings:
            if nearby_keyword is not None:
                finding.detection_reason = (
                    f"Found near `{nearby_keyword}` statement. "
                    "Potential PII exposure via logging."
                )
            all_findings.append(finding)

    return all_findings


def scan_directory(path: str) -> ScanResult:
    """Recursively scan a directory for PII findings."""
    all_findings: list[Finding] = []
    files_scanned = 0

    try:
        for dirpath, dirnames, filenames in os.walk(path):
            # Prune ignored directories in-place so os.walk won't descend into them
            dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]

            for filename in filenames:
                _, ext = os.path.splitext(filename)
                if ext not in SUPPORTED_EXTENSIONS:
                    continue

                filepath = os.path.join(dirpath, filename)
                findings = scan_file(filepath)
                all_findings.extend(findings)
                files_scanned += 1

    except FileNotFoundError:
        print(f"Warning: directory not found: {path}", file=sys.stderr)

    high_count = sum(1 for f in all_findings if f.severity == Severity.HIGH)
    medium_count = sum(1 for f in all_findings if f.severity == Severity.MEDIUM)
    low_count = sum(1 for f in all_findings if f.severity == Severity.LOW)

    return ScanResult(
        scan_id=str(uuid.uuid4()),
        files_scanned=files_scanned,
        total_findings=len(all_findings),
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        findings=all_findings,
    )
