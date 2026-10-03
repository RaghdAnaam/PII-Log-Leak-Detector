import re
from backend.app.detectors.base import PIIDetector
from backend.app.models.findings import Finding, PIIType, Severity
from backend.app.masking.maskers import mask_email

# RFC-5321 simplified email pattern
_EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
)

_RECOMMENDED_FIX = (
    "Log a non-sensitive identifier instead of the email address (e.g. customer_id)"
)


class EmailDetector(PIIDetector):
    def detect(self, text: str, file: str = "", line_offset: int = 1) -> list[Finding]:
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
