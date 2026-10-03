"""
Malaysian IC (NRIC / MyKad) number detector.

Malaysian identity card numbers follow the format ``YYMMDD-PB-XXXX`` where:
- ``YYMMDD`` is the date of birth
- ``PB`` is a two-digit state/country code (01–16 for Malaysian states)
- ``XXXX`` is a four-digit sequence number

Two patterns are applied:
1. Hyphenated format ``YYMMDD-PB-XXXX`` — high confidence.
2. Plain 12-digit format (no separators) with validated date/state fields — medium confidence.
"""

import re

from backend.app.detectors.base import PIIDetector
from backend.app.masking.maskers import mask_ic
from backend.app.models.findings import Finding, PIIType, Severity

# Hyphenated format: YYMMDD-PB-XXXX  (state codes 01-16)
_IC_HYPHEN_RE = re.compile(
    r"\b(\d{6})-?(0[1-9]|1[0-6])-?(\d{4})\b"
)

# No-separator format: 12 consecutive digits that look like a valid IC
_IC_PLAIN_RE = re.compile(
    r"\b(\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])(?:0[1-9]|1[0-6])\d{4})\b"
)

_RECOMMENDED_FIX = (
    "Do not log government ID numbers. Use an internal customer ID instead."
)


class ICDetector(PIIDetector):
    """Detector for Malaysian IC (NRIC / MyKad) numbers.

    Applies hyphenated pattern first (high confidence), then a plain 12-digit
    pattern (medium confidence). Overlapping plain matches are suppressed.
    """

    def detect(self, text: str, file: str = "", line_offset: int = 1) -> list[Finding]:
        """Scan *text* for Malaysian IC numbers and return a Finding for each match.

        Args:
            text: A single line of source code or log output.
            file: The file path this line belongs to (used in the Finding).
            line_offset: The 1-based line number of *text* within the file.

        Returns:
            A list of :class:`Finding` objects. All IC findings carry
            ``severity=HIGH`` regardless of confidence level, because IC numbers
            are among the most sensitive PII in the Malaysian context.
            Returns an empty list when no IC numbers are detected.
        """
        findings: list[Finding] = []
        seen_spans: list[tuple[int, int]] = []

        # Hyphenated — high confidence
        for match in _IC_HYPHEN_RE.finditer(text):
            value = match.group()
            seen_spans.append((match.start(), match.end()))
            findings.append(
                Finding(
                    pii_type=PIIType.MALAYSIAN_IC,
                    matched_value=value,
                    masked_value=mask_ic(value),
                    file=file,
                    line_number=line_offset,
                    column_number=match.start(),
                    confidence="high",
                    severity=Severity.HIGH,
                    detection_reason="Potential Malaysian IC number detected",
                    recommended_fix=_RECOMMENDED_FIX,
                )
            )

        # Plain 12-digit — medium confidence, skip overlaps
        for match in _IC_PLAIN_RE.finditer(text):
            if any(s <= match.start() < e or s < match.end() <= e for s, e in seen_spans):
                continue
            value = match.group()
            findings.append(
                Finding(
                    pii_type=PIIType.MALAYSIAN_IC,
                    matched_value=value,
                    masked_value=mask_ic(value),
                    file=file,
                    line_number=line_offset,
                    column_number=match.start(),
                    confidence="medium",
                    severity=Severity.HIGH,
                    detection_reason="Potential Malaysian IC number detected (no separators)",
                    recommended_fix=_RECOMMENDED_FIX,
                )
            )

        return findings
