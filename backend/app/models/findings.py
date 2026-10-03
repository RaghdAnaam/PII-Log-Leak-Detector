from enum import Enum

from pydantic import BaseModel


class PIIType(str, Enum):
    EMAIL = "Email"
    PHONE = "Phone"
    MALAYSIAN_IC = "Malaysian IC"
    CREDIT_CARD = "Credit Card"
    ACCOUNT_NUMBER = "Account Number"


class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Finding(BaseModel):
    """Internal model — includes matched_value for masking logic. NEVER serialize to API."""
    pii_type: PIIType
    matched_value: str          # Raw detected value — internal use only
    masked_value: str           # Safe display value
    file: str
    line_number: int
    column_number: int | None = None
    confidence: str             # "high" | "medium" | "low"
    severity: Severity
    detection_reason: str
    recommended_fix: str


class FindingResponse(BaseModel):
    """API response model — matched_value field does NOT EXIST. Safe to serialize."""
    pii_type: PIIType
    masked_value: str
    file: str
    line_number: int
    column_number: int | None = None
    confidence: str
    severity: Severity
    detection_reason: str
    recommended_fix: str

    @classmethod
    def from_finding(cls, finding: Finding) -> "FindingResponse":
        return cls(
            pii_type=finding.pii_type,
            masked_value=finding.masked_value,
            file=finding.file,
            line_number=finding.line_number,
            column_number=finding.column_number,
            confidence=finding.confidence,
            severity=finding.severity,
            detection_reason=finding.detection_reason,
            recommended_fix=finding.recommended_fix,
        )


class ScanResult(BaseModel):
    """Internal scan result — contains Finding objects with matched_value."""
    scan_id: str
    files_scanned: int
    total_findings: int
    high_count: int
    medium_count: int
    low_count: int
    findings: list[Finding]

    def to_response(self) -> "ScanResultResponse":
        return ScanResultResponse(
            scan_id=self.scan_id,
            files_scanned=self.files_scanned,
            total_findings=self.total_findings,
            high_count=self.high_count,
            medium_count=self.medium_count,
            low_count=self.low_count,
            findings=[FindingResponse.from_finding(f) for f in self.findings],
        )


class ScanResultResponse(BaseModel):
    """API response model — all findings are FindingResponse (no matched_value)."""
    scan_id: str
    files_scanned: int
    total_findings: int
    high_count: int
    medium_count: int
    low_count: int
    findings: list[FindingResponse]
