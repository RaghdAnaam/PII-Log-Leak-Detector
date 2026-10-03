"""
Account number PII detector.

Uses a contextual pattern: looks for keywords such as ``account``, ``acc_no``,
or ``account_id`` followed by a separator (``:``, ``=``, ``-``) and then an
alphanumeric value of 6–20 characters.

This approach is intentionally context-driven rather than matching bare digit
strings, which would generate a very high false-positive rate. The trade-off
is that account numbers without a recognisable keyword prefix will not be
detected (false negatives). Confidence is therefore reported as ``medium``.
"""

import re

from backend.app.detectors.base import PIIDetector
from backend.app.masking.maskers import mask_account_number
from backend.app.models.findings import Finding, PIIType, Severity

# Contextual pattern: account keyword followed by a numeric/alphanumeric value
_ACCOUNT_RE = re.compile(
    r"(?i)(?:account[_\s\-]?(?:no|number|num|id)?|acc(?:t)?)[:\s=\-]*([A-Z0-9\-]{6,20})",
    re.IGNORECASE,
)

_RECOMMENDED_FIX = (
    "Use a masked or tokenised account reference instead of the full account number."
)


class AccountNumberDetector(PIIDetector):
    """Detector for account numbers.

    Relies on keyword context to reduce false positives. All findings are
    ``confidence="medium"`` and ``severity=MEDIUM``.
    """

    def detect(self, text: str, file: str = "", line_offset: int = 1) -> list[Finding]:
        """Scan *text* for account numbers and return a Finding for each match.

        The detector matches capture group 1 (the number value itself), not the
        full keyword-plus-number span, so ``column_number`` points to the start
        of the numeric value rather than the keyword.

        Args:
            text: A single line of source code or log output.
            file: The file path this line belongs to (used in the Finding).
            line_offset: The 1-based line number of *text* within the file.

        Returns:
            A list of :class:`Finding` objects, or an empty list when no
            account number context is found.
        """
        findings: list[Finding] = []

        for match in _ACCOUNT_RE.finditer(text):
            value = match.group(1)  # The account number itself (capture group 1)
            if not value:
                continue
            findings.append(
                Finding(
                    pii_type=PIIType.ACCOUNT_NUMBER,
                    matched_value=value,
                    masked_value=mask_account_number(value),
                    file=file,
                    line_number=line_offset,
                    column_number=match.start(1),
                    confidence="medium",
                    severity=Severity.MEDIUM,
                    detection_reason="Potential account number detected",
                    recommended_fix=_RECOMMENDED_FIX,
                )
            )

        return findings
