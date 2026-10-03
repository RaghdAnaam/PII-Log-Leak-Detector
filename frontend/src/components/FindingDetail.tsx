import type { FindingResponse } from "../types";

interface FindingDetailProps {
  finding: FindingResponse | null;
  onClose: () => void;
}

function Row({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-xs font-medium text-gray-500 uppercase tracking-wider">
        {label}
      </span>
      <span className="text-sm text-gray-200 font-mono break-all">{value}</span>
    </div>
  );
}

function Section({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="border-t border-gray-700 pt-4 flex flex-col gap-1">
      <span className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-1">
        {label}
      </span>
      {children}
    </div>
  );
}

export function FindingDetail({ finding, onClose }: FindingDetailProps) {
  if (!finding) return null;

  return (
    <div className="fixed top-0 right-0 h-full w-80 bg-gray-900 border-l border-gray-700 shadow-2xl z-50 flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-4 border-b border-gray-700">
        <h2 className="text-sm font-semibold text-gray-100">Finding Detail</h2>
        <button
          onClick={onClose}
          className="text-gray-500 hover:text-gray-200 text-lg leading-none transition-colors"
          aria-label="Close"
        >
          ×
        </button>
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto px-5 py-4 flex flex-col gap-4">
        <div className="flex flex-col gap-3">
          <Row label="PII Type" value={finding.pii_type} />
          <Row label="Severity" value={finding.severity} />
          <Row label="File" value={finding.file} />
          <Row label="Line" value={finding.line_number} />
          <Row label="Confidence" value={finding.confidence} />
        </div>

        <Section label="Detection Reason">
          <p className="text-sm text-gray-300 leading-relaxed">
            {finding.detection_reason}
          </p>
        </Section>

        <Section label="Masked Value">
          <code className="text-sm text-green-400 font-mono break-all bg-gray-800 rounded px-2 py-1">
            {finding.masked_value}
          </code>
        </Section>

        <Section label="Recommended Fix">
          <p className="text-sm text-gray-300 leading-relaxed">
            {finding.recommended_fix}
          </p>
        </Section>
      </div>
    </div>
  );
}
