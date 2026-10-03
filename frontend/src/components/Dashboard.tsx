import { useState } from "react";
import type { FindingResponse, ScanResultResponse } from "../types";
import { scanDemo, fixScan } from "../api/client";
import { SummaryCards } from "./SummaryCards";
import { ScanControls } from "./ScanControls";
import { FindingsTable } from "./FindingsTable";
import { FindingDetail } from "./FindingDetail";

export function Dashboard() {
  const [scanResult, setScanResult] = useState<ScanResultResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<FindingResponse | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [isFixed, setIsFixed] = useState(false);

  async function handleScan() {
    setIsLoading(true);
    setError(null);
    setSelectedFinding(null);
    setIsFixed(false);
    try {
      const result = await scanDemo();
      setScanResult(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Scan failed.");
    } finally {
      setIsLoading(false);
    }
  }

  async function handleFix(scanId: string) {
    setIsLoading(true);
    setError(null);
    setSelectedFinding(null);
    try {
      const result = await fixScan(scanId);
      setScanResult(result);
      setIsFixed(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Fix failed.");
    } finally {
      setIsLoading(false);
    }
  }

  const hasFindings = (scanResult?.total_findings ?? 0) > 0;
  const isClean =
    scanResult !== null && scanResult.total_findings === 0;

  return (
    <div className="flex flex-col gap-6">
      {/* Summary Cards */}
      <SummaryCards result={scanResult} />

      {/* Controls row */}
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <ScanControls
          onScan={handleScan}
          onFix={handleFix}
          scanId={scanResult?.scan_id ?? null}
          isLoading={isLoading}
          hasFindings={hasFindings}
        />
        {scanResult !== null && !isClean && (
          <div className="flex items-center gap-2">
            <label
              htmlFor="severity-filter"
              className="text-xs text-gray-400 font-medium uppercase tracking-wider"
            >
              Filter:
            </label>
            <select
              id="severity-filter"
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value);
                setSelectedFinding(null);
              }}
              className="bg-gray-800 border border-gray-700 text-gray-200 text-sm rounded px-3 py-1.5 focus:outline-none focus:ring-1 focus:ring-red-500"
            >
              <option value="ALL">All</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
          </div>
        )}
      </div>

      {/* Error banner */}
      {error && (
        <div className="rounded-md bg-red-950 border border-red-800 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      )}

      {/* Loading state */}
      {isLoading && (
        <div className="rounded-md bg-gray-800 border border-gray-700 px-4 py-6 text-center text-gray-400 text-sm animate-pulse">
          Scanning files for PII leaks…
        </div>
      )}

      {/* Clean state */}
      {!isLoading && isClean && (
        <div className="rounded-lg bg-green-950 border border-green-800 px-6 py-6 flex flex-col gap-1">
          <p className="text-green-400 font-semibold text-base">
            ✓ No potential PII leaks detected.
          </p>
          <p className="text-green-600 text-sm">
            Files scanned: {scanResult.files_scanned}
          </p>
          <p className="text-green-600 text-sm">
            {isFixed
              ? "Fix applied — scan completed successfully."
              : "Scan completed successfully."}
          </p>
        </div>
      )}

      {/* Findings table + detail panel */}
      {!isLoading && scanResult !== null && hasFindings && (
        <div
          className={`flex gap-4 transition-all ${
            selectedFinding ? "mr-84" : ""
          }`}
        >
          <div className="flex-1 min-w-0">
            <FindingsTable
              findings={scanResult.findings}
              onSelect={setSelectedFinding}
              selectedFinding={selectedFinding}
              severityFilter={severityFilter}
            />
          </div>
        </div>
      )}

      {/* Side panel */}
      <FindingDetail
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
      />
    </div>
  );
}
