"""
Email PII detector.

Detects email addresses in source code and log lines using an RFC-5321-simplified
regular expression. All matches are treated as high-confidence because the
local-part + '@' + domain structure is highly distinctive.
"""

import re

from backend.app.detectors.base import PIIDetector
from backend.app.masking.maskers import mask_email
from backend.app.models.findings import Finding, PIIType, Severity

# RFC-5321 simplified email pattern — covers the vast majority of real addresses.
# Does not validate the TLD exhaustively; avoids false negatives from new TLDs.
_EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
)

_RECOMMENDED_FIX = (
    "Log a non-sensitive identifier instead of the email address (e.g. customer_id)"
)


class EmailDetector(PIIDetector):
    """Detector for email addresses.

    Uses a single high-confidence regex pattern. Every match is classified as
    HIGH severity because email addresses are almost always PII.
    """

    def detect(self, text: str, file: str = "", line_offset: int = 1) -> list[Finding]:
        """Scan *text* for email addresses and return a Finding for each match.

        Args:
            text: A single line of source code or log output.
            file: The file path this line belongs to (used in the Finding).
            line_offset: The 1-based line number of *text* within the file.

        Returns:
            A list of :class:`Finding` objects, one per email address found.
            Returns an empty list when no emails are detected.
        """
        findings: list[Finding] = []
        for match in _EMAIL_RE.finditer(text):
            value = match.group()
            findings.append(
                Finding(
                    pii_type=PIIType.EMAIL,
                    matched_value=value,
                    masked_value=mask_email(value),
                    file=file,
                    line_number=line_offset,
                    column_number=match.start(),
                    confidence="high",
                    severity=Severity.HIGH,
                    detection_reason="Potential email address detected",
                    recommended_fix=_RECOMMENDED_FIX,
                )
            )
        return findings
