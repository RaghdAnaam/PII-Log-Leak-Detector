import re
from backend.app.detectors.base import PIIDetector
from backend.app.models.findings import Finding, PIIType, Severity
from backend.app.masking.maskers import mask_account_number

# Contextual pattern: account keyword followed by a numeric/alphanumeric value
_ACCOUNT_RE = re.compile(
    r"(?i)(?:account[_\s\-]?(?:no|number|num|id)?|acc(?:t)?)[:\s=\-]*([A-Z0-9\-]{6,20})",
    re.IGNORECASE,
)

_RECOMMENDED_FIX = (
    "Use a masked or tokenised account reference instead of the full account number."
)


class AccountNumberDetector(PIIDetector):
    def detect(self, text: str, file: str = "", line_offset: int = 1) -> list[Finding]:
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
