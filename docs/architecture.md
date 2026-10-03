# Architecture

## Overview

PII Log Leak Detector is structured as a **single detection engine consumed by two interfaces**: a CLI tool and a FastAPI web backend. The engine has no dependency on either interface — it is a plain Python package that can be imported anywhere.

```
┌─────────────────────────────────────────────────────┐
│                  Interfaces                         │
│                                                     │
│   ┌─────────────────┐   ┌─────────────────────┐    │
│   │   pii-scan CLI  │   │   FastAPI Backend   │    │
│   │   (Click/Rich)  │   │   (Uvicorn + CORS)  │    │
│   └────────┬────────┘   └──────────┬──────────┘    │
│            │                       │                │
│            └──────────┬────────────┘                │
│                       │ direct Python import        │
└───────────────────────┼─────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────┐
│               Detection Engine                      │
│                                                     │
│  FileScanner / LogScanner                           │
│   │                                                 │
│   ├─► EmailDetector      → mask_email()             │
│   ├─► PhoneDetector      → mask_phone()             │
│   ├─► ICDetector         → mask_ic()                │
│   ├─► CreditCardDetector → mask_card_number()       │
│   └─► AccountNumberDetector → mask_account_number() │
│                                                     │
│  Returns: list[Finding]  (internal model)           │
└─────────────────────────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────┐
│                  Model Layer                        │
│                                                     │
│  Finding (internal)  →  FindingResponse (API)       │
│  ScanResult (internal) → ScanResultResponse (API)   │
│                                                     │
│  matched_value exists only in Finding.              │
│  FindingResponse has no matched_value field.        │
└─────────────────────────────────────────────────────┘
```

---

## Component Descriptions

### 1. Detection Engine

**Files:** `backend/app/detectors/`, `backend/app/scanner/`, `backend/app/masking/`

The detection engine is a self-contained Python package. It has no FastAPI imports, no HTTP dependencies, and no side effects beyond reading files. This means:

- The CLI can import it directly without starting a server.
- Tests can call it without spinning up a web server.
- The engine can be extracted and published as a standalone library.

**Scan pipeline (per file):**

```
open file → read lines → for each line:
    run all detectors → collect Finding objects
    check ±3-line context window for logging keywords
    enrich detection_reason if near a log statement
→ aggregate findings into ScanResult
```

**Log scan pipeline:**

```
open log file → read lines → for each line:
    run all detectors → collect Finding objects
    override detection_reason = "Found in application log file"
→ aggregate findings into ScanResult
```

### 2. Detectors

Each detector is a subclass of [`PIIDetector`](../backend/app/detectors/base.py) (abstract base class). Every detector:

1. Compiles one or more regular expressions at module load time (not per call).
2. Implements `detect(text, file, line_offset) → list[Finding]`.
3. Never stores state between calls — each call is independent.
4. Uses overlap-tracking (`seen_spans`) when running multiple patterns on the same line to avoid duplicate findings.

| Detector | Patterns | Confidence |
|---|---|---|
| `EmailDetector` | RFC-5321 simplified regex | high |
| `PhoneDetector` | Malaysian `+60`/`01X` (high), generic 8-15 digit (medium) | high / medium |
| `ICDetector` | Hyphenated `YYMMDD-PB-XXXX` (high), plain 12-digit (medium) | high / medium |
| `CreditCardDetector` | Visa/MC/Amex separated and plain formats | high |
| `AccountNumberDetector` | Contextual: `account:`, `acc_no=`, etc. followed by alphanumeric | medium |

### 3. Maskers

**File:** `backend/app/masking/maskers.py`

Each masker takes a raw PII string and returns a safe display string. Masking is deterministic and one-way. The raw value is never logged, stored, or returned to clients.

| Masker | Example Input | Example Output |
|---|---|---|
| `mask_email` | `john@example.com` | `j***@example.com` |
| `mask_phone` | `+60121234567` | `+601*****67` |
| `mask_ic` | `901231-14-5678` | `901231-**-****` |
| `mask_card_number` | `4111111111111111` | `4111 **** **** 1111` |
| `mask_account_number` | `ACC-1234567890` | `ACC-******7890` |

### 4. Model Layer — Two-Model Security Pattern

**File:** `backend/app/models/findings.py`

The most important security decision in the codebase is the two-model pattern:

```
Finding (internal Pydantic model)
  ├── pii_type
  ├── matched_value   ← RAW PII — internal only
  ├── masked_value
  ├── file
  ├── line_number
  └── ...

FindingResponse (API Pydantic model)
  ├── pii_type
  │   (NO matched_value field)
  ├── masked_value
  ├── file
  ├── line_number
  └── ...
```

`matched_value` is **structurally absent** from `FindingResponse`. It is not redacted at serialisation time — it simply does not exist in the output model. This means no code path, no matter how buggy, can accidentally include the raw PII value in an API response.

The conversion happens in `ScanResult.to_response()`:

```python
findings=[FindingResponse.from_finding(f) for f in self.findings]
```

`from_finding` explicitly copies only the safe fields.

### 5. FastAPI Backend

**Files:** `backend/app/main.py`, `backend/app/api/routes_scan.py`

The backend is a thin HTTP wrapper around the detection engine. It:

1. Accepts requests from the React frontend.
2. Calls the same `scan_directory()` / `run_demo_scan()` functions the CLI uses.
3. Stores `ScanResult` objects in `app.state.scan_results` (in-memory dict, keyed by UUID).
4. Converts results to `ScanResultResponse` before returning, using `response_model=ScanResultResponse` on every route as a second-line serialisation safeguard.

**Routes:**

```
POST /api/scan/demo          → scan demo_vulnerable_app, return masked findings
GET  /api/scan/{scan_id}     → retrieve cached scan result
POST /api/scan/{scan_id}/fix → apply demo fix, rescan, return new result
POST /api/scan/{scan_id}/rescan → rescan without fix
GET  /health                 → {"status": "ok"}
```

### 6. Demo Fix Workflow (`_fixed/` directory)

**Files:** `backend/app/services/fix_service.py`, `demo_vulnerable_app/_fixed/`

The fix workflow is intentionally narrow and safe:

```
User clicks "Fix Demo"
  → API calls apply_demo_fix()
  → For each file in ["customer_service.py", "payments.py", "errors.py", "utils.py"]:
      copy demo_vulnerable_app/_fixed/<file> → demo_vulnerable_app/<file>
  → Rescan demo_vulnerable_app/
  → Return new ScanResult (expected: 0 findings)
```

The `_fixed/` directory contains pre-written clean versions of the demo files where PII values are replaced with non-sensitive identifiers (e.g. `customer_id` instead of `email`). The fix service:

- **Only writes inside `demo_vulnerable_app/`** — no other directory is touched.
- **Does not execute any code** — it only calls `shutil.copy2`.
- **Does not apply AI-generated or dynamic patches** — the clean files are static and version-controlled.
- **Does not modify files uploaded by users** — it operates exclusively on the bundled demo path.

The `_fixed/` directory is listed in `IGNORED_DIRS` in `config.py`, so it is never scanned as vulnerable.

### 7. CLI

**File:** `cli/pii_scan_cli.py`

The CLI uses Click for argument parsing and Rich for formatted terminal output. It imports the detection engine directly — no HTTP requests, no server required.

Commands:

```
pii-scan scan <path>       → scan source files in a directory
pii-scan scan-log <path>   → scan a log file
pii-scan fix <path>        → apply demo fix and rescan
```

### 8. React Frontend

**Directory:** `frontend/src/`

The frontend is a single-page Vite + React + TypeScript application. It communicates with the backend via REST and renders the scan results in a dashboard layout:

```
App.tsx
  └─ Dashboard.tsx
       ├─ SummaryCards.tsx     ← findings count, HIGH/MEDIUM/LOW badges
       ├─ ScanControls.tsx     ← Scan / Fix / Rescan buttons
       └─ FindingsTable.tsx    ← sortable table, masked values only
```

---

## Data Flow Summary

### Scan request (web)

```
Browser clicks "Scan"
  → POST /api/scan/demo
  → FastAPI: run_demo_scan()
  → scan_directory("demo_vulnerable_app/")
  → for each .py file: scan_file()
     → each line through all 5 detectors
     → matches → Finding(matched_value, masked_value, ...)
  → ScanResult(findings=[Finding, ...])
  → ScanResult.to_response()
  → ScanResultResponse(findings=[FindingResponse, ...])   ← no matched_value
  → JSON response to browser
```

### Scan request (CLI)

```
pii-scan scan ./demo_vulnerable_app
  → scan_directory("./demo_vulnerable_app")   ← same function
  → list[Finding]
  → CLI renders masked_value with Rich table   ← matched_value is never printed
```

---

## Security Decisions Summary

| Decision | Reason |
|---|---|
| `matched_value` absent from `FindingResponse` | Structural guarantee — no serialisation bug can expose raw PII |
| `response_model=ScanResultResponse` on every route | FastAPI re-serialises through the response model as defence-in-depth |
| Fix limited to `demo_vulnerable_app/_fixed/` | Predictable, safe, no risk of corrupting arbitrary user files |
| No uploaded code is executed | Files read as text strings; no `eval`, `exec`, or subprocess |
| ZIP path traversal checks in `security.py` | Prevents malicious archives from writing outside the temp directory |
| `_fixed/` in `IGNORED_DIRS` | Prevents the clean versions from being scanned as if they were vulnerable |
| Stateless — no database | No PII ever written to persistent storage |
