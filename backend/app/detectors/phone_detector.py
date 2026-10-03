import re
from backend.app.detectors.base import PIIDetector
from backend.app.models.findings import Finding, PIIType, Severity
from backend.app.masking.maskers import mask_phone

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
    def detect(self, text: str, file: str = "", line_offset: int = 1) -> list[Finding]:
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
