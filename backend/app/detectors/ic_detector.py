import re
from backend.app.detectors.base import PIIDetector
from backend.app.models.findings import Finding, PIIType, Severity
from backend.app.masking.maskers import mask_ic

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
    def detect(self, text: str, file: str = "", line_offset: int = 1) -> list[Finding]:
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
