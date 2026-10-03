import type { FindingResponse, Severity } from "../types";

interface FindingsTableProps {
  findings: FindingResponse[];
  onSelect: (finding: FindingResponse) => void;
  selectedFinding: FindingResponse | null;
  severityFilter: string;
}

const SEVERITY_BADGE: Record<Severity, string> = {
  HIGH: "bg-red-100 text-red-700",
  MEDIUM: "bg-yellow-100 text-yellow-700",
  LOW: "bg-blue-100 text-blue-700",
};

function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-block px-2 py-0.5 rounded text-xs font-semibold ${SEVERITY_BADGE[severity]}`}
    >
      {severity}
    </span>
  );
}

export function FindingsTable({
  findings,
  onSelect,
  selectedFinding,
  severityFilter,
}: FindingsTableProps) {
  const filtered =
    severityFilter === "ALL"
      ? findings
      : findings.filter((f) => f.severity === severityFilter);

  return (
    <div className="rounded-lg border border-gray-700 overflow-hidden">
      <table className="w-full text-sm">
        <thead>
          <tr className="bg-gray-800 text-gray-400 text-xs uppercase tracking-wider">
            <th className="px-4 py-3 text-left font-medium">Severity</th>
            <th className="px-4 py-3 text-left font-medium">PII Type</th>
            <th className="px-4 py-3 text-left font-medium">File</th>
            <th className="px-4 py-3 text-left font-medium">Line</th>
            <th className="px-4 py-3 text-left font-medium">Preview</th>
          </tr>
        </thead>
        <tbody>
          {filtered.length === 0 ? (
            <tr>
              <td
                colSpan={5}
                className="px-4 py-8 text-center text-gray-500 bg-gray-900"
              >
                No findings match the current filter.
              </td>
            </tr>
          ) : (
            filtered.map((finding, idx) => {
              const isSelected =
                selectedFinding !== null &&
                selectedFinding.file === finding.file &&
                selectedFinding.line_number === finding.line_number &&
                selectedFinding.pii_type === finding.pii_type;

              return (
                <tr
                  key={idx}
                  onClick={() => onSelect(finding)}
                  className={`border-t border-gray-700 cursor-pointer transition-colors ${
                    isSelected
                      ? "bg-gray-700"
                      : "bg-gray-900 hover:bg-gray-800"
                  }`}
                >
                  <td className="px-4 py-3">
                    <SeverityBadge severity={finding.severity} />
                  </td>
                  <td className="px-4 py-3 text-gray-200">{finding.pii_type}</td>
                  <td className="px-4 py-3 text-gray-400 font-mono text-xs">
                    {finding.file}
                  </td>
                  <td className="px-4 py-3 text-gray-400">{finding.line_number}</td>
                  <td className="px-4 py-3 text-gray-300 font-mono text-xs">
                    {finding.masked_value}
                  </td>
                </tr>
              );
            })
          )}
        </tbody>
      </table>
    </div>
  );
}
