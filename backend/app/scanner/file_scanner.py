"""
File scanner — scans source code files in a directory tree for PII.

Entry points:
- :func:`scan_file` — scan a single file, one line at a time.
- :func:`scan_directory` — recursively walk a directory and aggregate results.

Context enrichment: if a PII match is found near a logging statement (within
±3 lines), the finding's ``detection_reason`` is updated to note the proximity,
indicating the PII may be actively emitted to logs.
"""

import os
import sys
import uuid

from backend.app.core.config import IGNORED_DIRS, SUPPORTED_EXTENSIONS
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
    """Scan a single source file for PII findings, one line at a time.

    Reads the file as UTF-8. Skips the file silently (with a stderr warning)
    if it cannot be decoded or does not exist.

    For each line that contains a PII match, the ±3-line context window is
    inspected for logging keywords. When found, the finding's
    ``detection_reason`` is updated to flag proximity to a log statement.

    Args:
        path: Absolute or relative path to the file to scan.

    Returns:
        A flat list of :class:`Finding` objects from all lines in the file.
        Returns an empty list if the file is empty, unreadable, or clean.
    """
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
    """Recursively scan a directory tree for PII in supported file types.

    Uses :func:`os.walk` to traverse the directory. Subdirectories listed in
    ``IGNORED_DIRS`` (e.g. ``.venv``, ``node_modules``, ``_fixed``) are pruned
    before descent. Only files whose extension is in ``SUPPORTED_EXTENSIONS``
    are scanned.

    Args:
        path: Absolute or relative path to the root directory to scan.

    Returns:
        A :class:`ScanResult` containing all findings aggregated across
        every scanned file, with per-severity counts and a fresh UUID
        ``scan_id``. Returns a zero-finding result if the directory is
        empty or not found.
    """
    all_findings: list[Finding] = []
    files_scanned = 0

    # Resolve the scan root once so we can strip it from every filepath,
    # giving findings a clean relative path (e.g. "payments.py" instead of
    # "/Users/.../demo_vulnerable_app/payments.py").
    abs_root = os.path.realpath(path) + os.sep

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

                # Replace the absolute path stored in each finding with a path
                # relative to the scan root — cleaner for display in CLI and UI.
                abs_filepath = os.path.realpath(filepath)
                display_path = (
                    abs_filepath[len(abs_root):]
                    if abs_filepath.startswith(abs_root)
                    else filepath
                )
                for finding in findings:
                    finding.file = display_path

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
