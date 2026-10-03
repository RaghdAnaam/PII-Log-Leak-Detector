"""
Credit/debit card number detector.

Supports the four most common card formats:
- Visa / Mastercard / Discover: 16-digit grouped as 4-4-4-4 (separated or plain).
- American Express: 15-digit grouped as 4-6-5 (separated or plain).

Patterns are applied in preference order: separated formats first (higher visual
clarity), then plain digit strings. Overlap-tracking prevents duplicate findings
when the same number matches more than one pattern.

Note: Luhn checksum validation is intentionally omitted to avoid false negatives
from transcription errors in real log data.
"""

import re

from backend.app.detectors.base import PIIDetector
from backend.app.masking.maskers import mask_card_number
from backend.app.models.findings import Finding, PIIType, Severity

# 4 groups of 4 digits separated by spaces or hyphens
_CARD_SEP_RE = re.compile(
    r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))"
    r"[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}\b"
)

# 16 consecutive digits starting with common card prefixes
_CARD_PLAIN_RE = re.compile(
    r"\b(?:4\d{15}|5[1-5]\d{14}|6(?:011|5\d{2})\d{12})\b"
)

# Amex: 15-digit, format 4-6-5
_AMEX_SEP_RE = re.compile(
    r"\b3[47]\d{2}[\s\-]\d{6}[\s\-]\d{5}\b"
)

_AMEX_PLAIN_RE = re.compile(
    r"\b3[47]\d{13}\b"
)

_RECOMMENDED_FIX = (
    "Never log payment card numbers. "
    "Log only a non-sensitive transaction reference."
)


class CreditCardDetector(PIIDetector):
    """Detector for credit and debit card numbers.

    Checks Visa, Mastercard, Discover, and Amex card formats using prefix-aware
    patterns. Overlap-tracking ensures each card number is reported once.
    """

    def detect(self, text: str, file: str = "", line_offset: int = 1) -> list[Finding]:
        """Scan *text* for card numbers and return a Finding for each match.

        Args:
            text: A single line of source code or log output.
            file: The file path this line belongs to (used in the Finding).
            line_offset: The 1-based line number of *text* within the file.

        Returns:
            A list of :class:`Finding` objects, all with ``confidence="high"``
            and ``severity=HIGH``. Returns an empty list when no card numbers
            are detected.
        """
        findings: list[Finding] = []
        seen_spans: list[tuple[int, int]] = []

        patterns = [_CARD_SEP_RE, _AMEX_SEP_RE, _CARD_PLAIN_RE, _AMEX_PLAIN_RE]

        for pattern in patterns:
            for match in pattern.finditer(text):
                # Skip overlaps
                if any(s <= match.start() < e or s < match.end() <= e for s, e in seen_spans):
                    continue
                value = match.group()
                seen_spans.append((match.start(), match.end()))
                findings.append(
                    Finding(
                        pii_type=PIIType.CREDIT_CARD,
                        matched_value=value,
                        masked_value=mask_card_number(value),
                        file=file,
                        line_number=line_offset,
                        column_number=match.start(),
                        confidence="high",
                        severity=Severity.HIGH,
                        detection_reason="Potential credit card number detected",
                        recommended_fix=_RECOMMENDED_FIX,
                    )
                )

        return findings
