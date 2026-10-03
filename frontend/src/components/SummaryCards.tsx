import type { ScanResultResponse } from "../types";

interface SummaryCardsProps {
  result: ScanResultResponse | null;
}

interface CardProps {
  label: string;
  value: string | number;
  colorClass: string;
  valueColorClass?: string;
}

function Card({ label, value, colorClass, valueColorClass }: CardProps) {
  return (
    <div
      className={`rounded-lg border p-4 flex flex-col gap-1 ${colorClass}`}
    >
      <span className="text-xs font-medium uppercase tracking-wider text-gray-400">
        {label}
      </span>
      <span
        className={`text-3xl font-bold ${valueColorClass ?? "text-gray-100"}`}
      >
        {value}
      </span>
    </div>
  );
}

export function SummaryCards({ result }: SummaryCardsProps) {
  const statusLabel =
    result === null
      ? "Not Scanned"
      : result.total_findings === 0
      ? "Clean ✓"
      : "Issues Found";

  const statusColor =
    result === null
      ? "text-gray-400"
      : result.total_findings === 0
      ? "text-green-400"
      : "text-red-400";

  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
      <Card
        label="Total Findings"
        value={result?.total_findings ?? "—"}
        colorClass="bg-gray-800 border-gray-700"
      />
      <Card
        label="High Severity"
        value={result?.high_count ?? "—"}
        colorClass="bg-red-950 border-red-900"
        valueColorClass={result && result.high_count > 0 ? "text-red-400" : "text-gray-100"}
      />
      <Card
        label="Files Scanned"
        value={result?.files_scanned ?? "—"}
        colorClass="bg-blue-950 border-blue-900"
        valueColorClass="text-blue-300"
      />
      <Card
        label="Scan Status"
        value={statusLabel}
        colorClass="bg-gray-800 border-gray-700"
        valueColorClass={statusColor}
      />
    </div>
  );
}
