"""
Phone number PII detector.

Applies two patterns:
1. High-confidence Malaysian numbers (+60 prefix or 01X local format).
2. Medium-confidence generic 8–15 digit pattern for international numbers.

Malaysian matches are checked first; any overlapping generic match is suppressed
to prevent duplicate findings on the same span.

Severity is elevated to HIGH when the line contains a logging keyword such as
``logger.info`` or ``print(``, indicating the number is about to be emitted
to a log.
"""

import re

from backend.app.detectors.base import PIIDetector
from backend.app.masking.maskers import mask_phone
from backend.app.models.findings import Finding, PIIType, Severity

# Malaysian +60 patterns (high confidence)
_MY_PHONE_RE = re.compile(
    r"(?:\+60[\s\-]?1[0-9][\s\-]?\d{3,4}[\s\-]?\d{4}"   # +60 1X-XXXX-XXXX
    r"|\+60[\s\-]?\d{1,2}[\s\-]?\d{6,8}"                  # +60-XX-XXXXXXXX
    r"|0(?:1[0-9])[\s\-]?\d{3,4}[\s\-]?\d{4}"             # 01X-XXXX-XXXX
    r"|01[0-9]\d{7,8})"                                    # 01XXXXXXXXX (no sep)
)

# Generic phone pattern (medium confidence) — 8-15 digits with optional separators
_GENERIC_PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?\d[\d\s\-\(\)\.]{7,18}\d)(?!\d)"
)

# Logging keywords that elevate severity
_LOG_KEYWORDS_RE = re.compile(
    r"\b(?:log(?:ged)?|print|debug|info|warn(?:ing)?|error|trace|console)\b",
    re.IGNORECASE,
)

_RECOMMENDED_FIX = "Log a non-sensitive identifier. Never log phone numbers."


class PhoneDetector(PIIDetector):
    """Detector for phone numbers.

    Two-pass detection: high-confidence Malaysian patterns first, then a
    generic fallback. Overlap-tracking prevents duplicate findings.
    """

    def detect(self, text: str, file: str = "", line_offset: int = 1) -> list[Finding]:
        """Scan *text* for phone numbers and return a Finding for each match.

        Args:
            text: A single line of source code or log output.
            file: The file path this line belongs to (used in the Finding).
            line_offset: The 1-based line number of *text* within the file.

        Returns:
            A list of :class:`Finding` objects. Malaysian numbers are returned
            with ``confidence="high"``; generic numbers with ``confidence="medium"``.
            Returns an empty list when no phone numbers are detected.
        """
        findings: list[Finding] = []
        seen_spans: list[tuple[int, int]] = []

        near_log_keyword = bool(_LOG_KEYWORDS_RE.search(text))

        # High-confidence Malaysian matches first
        for match in _MY_PHONE_RE.finditer(text):
            value = match.group().strip()
            span = (match.start(), match.end())
            seen_spans.append(span)
            severity = Severity.HIGH if near_log_keyword else Severity.MEDIUM
            findings.append(
                Finding(
                    pii_type=PIIType.PHONE,
                    matched_value=value,
                    masked_value=mask_phone(value),
                    file=file,
                    line_number=line_offset,
                    column_number=match.start(),
                    confidence="high",
                    severity=severity,
                    detection_reason="Potential Malaysian phone number detected",
                    recommended_fix=_RECOMMENDED_FIX,
                )
            )

        # Generic pattern — skip if already covered by a Malaysian match
        for match in _GENERIC_PHONE_RE.finditer(text):
            value = match.group().strip()
            # Skip if digits count < 8 after stripping non-digits
            digits = re.sub(r"\D", "", value)
            if len(digits) < 8:
                continue
            span = (match.start(), match.end())
            # Skip overlap with already-found Malaysian matches
            if any(s <= match.start() < e or s < match.end() <= e for s, e in seen_spans):
                continue
            severity = Severity.HIGH if near_log_keyword else Severity.MEDIUM
            findings.append(
                Finding(
                    pii_type=PIIType.PHONE,
                    matched_value=value,
                    masked_value=mask_phone(value),
                    file=file,
                    line_number=line_offset,
                    column_number=match.start(),
                    confidence="medium",
                    severity=severity,
                    detection_reason="Potential phone number detected",
                    recommended_fix=_RECOMMENDED_FIX,
                )
            )

        return findings
