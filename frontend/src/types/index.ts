export type PIIType =
  | "Email"
  | "Phone"
  | "Malaysian IC"
  | "Credit Card"
  | "Account Number";

export type Severity = "HIGH" | "MEDIUM" | "LOW";

export interface FindingResponse {
  pii_type: PIIType;
  masked_value: string;
  file: string;
  line_number: number;
  column_number?: number;
  confidence: string;
  severity: Severity;
  detection_reason: string;
  recommended_fix: string;
}

export interface ScanResultResponse {
  scan_id: string;
  files_scanned: number;
  total_findings: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  findings: FindingResponse[];
}
