interface ScanControlsProps {
  onScan: () => void;
  onFix: (scanId: string) => void;
  scanId: string | null;
  isLoading: boolean;
  hasFindings: boolean;
}

function Spinner() {
  return (
    <svg
      className="animate-spin h-4 w-4"
      xmlns="http://www.w3.org/2000/svg"
      fill="none"
      viewBox="0 0 24 24"
    >
      <circle
        className="opacity-25"
        cx="12"
        cy="12"
        r="10"
        stroke="currentColor"
        strokeWidth="4"
      />
      <path
        className="opacity-75"
        fill="currentColor"
        d="M4 12a8 8 0 018-8v8H4z"
      />
    </svg>
  );
}

export function ScanControls({
  onScan,
  onFix,
  scanId,
  isLoading,
  hasFindings,
}: ScanControlsProps) {
  const showFix = hasFindings && scanId !== null;

  return (
    <div className="flex items-center gap-3">
      <button
        onClick={onScan}
        disabled={isLoading}
        className="inline-flex items-center gap-2 px-4 py-2 rounded-md bg-red-600 hover:bg-red-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold text-sm transition-colors"
      >
        {isLoading && <Spinner />}
        {isLoading ? "Scanning…" : "Scan Demo Project"}
      </button>

      {showFix && (
        <button
          onClick={() => onFix(scanId!)}
          disabled={isLoading}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-md bg-gray-700 hover:bg-gray-600 disabled:opacity-50 disabled:cursor-not-allowed text-gray-100 font-semibold text-sm transition-colors border border-gray-600"
        >
          {isLoading && <Spinner />}
          Apply Demo Fix
        </button>
      )}
    </div>
  );
}
