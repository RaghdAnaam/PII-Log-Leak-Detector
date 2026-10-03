import uuid

from fastapi import APIRouter, HTTPException, Request

from backend.app.models.findings import ScanResultResponse
from backend.app.services.fix_service import apply_demo_fix
from backend.app.services.scan_service import run_demo_scan

router = APIRouter(prefix="/api")


# Security: response_model=ScanResultResponse is declared on every route.
# FastAPI uses this to re-serialise the return value through ScanResultResponse
# before sending it to the client. This is a defence-in-depth measure: even if
# a code path accidentally returned a ScanResult (which contains Finding objects
# with matched_value), FastAPI would silently drop any field not declared on
# ScanResultResponse. The primary protection is the two-model pattern in
# findings.py; this is the second line of defence.


@router.post("/scan/demo", response_model=ScanResultResponse)
async def scan_demo(request: Request):
    """
    Scan the demo vulnerable app. Returns masked findings only.

    Security: matched_value is structurally absent from ScanResultResponse —
    it is not redacted at serialisation time, it simply does not exist in the
    response model. result.to_response() performs the explicit conversion.
    """
    result = run_demo_scan()
    # Assign a scan_id and store in app state for subsequent fix/rescan calls.
    # The store is an in-memory dict — no PII is written to any persistent storage.
    scan_id = str(uuid.uuid4())
    result.scan_id = scan_id
    request.app.state.scan_results[scan_id] = result
    return result.to_response()


@router.get("/scan/{scan_id}", response_model=ScanResultResponse)
async def get_scan(scan_id: str, request: Request):
    """Retrieve a cached scan result by ID."""
    result = request.app.state.scan_results.get(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result.to_response()


@router.post("/scan/{scan_id}/fix", response_model=ScanResultResponse)
async def fix_scan(scan_id: str, request: Request):
    """
    Apply the demo fix (replaces vulnerable files with _fixed/ versions).
    Returns a fresh scan result after the fix.

    Security: this endpoint only works if a scan_id from a previous scan exists
    in the in-memory store. It does not accept a target path — it always calls
    apply_demo_fix(), which is hard-coded to operate only on demo_vulnerable_app/.
    There is no way to use this endpoint to modify arbitrary files.
    """
    if scan_id not in request.app.state.scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")

    # apply_demo_fix() copies pre-written _fixed/ files and rescans.
    # It does not execute code or apply dynamic patches.
    new_result = apply_demo_fix()
    new_scan_id = str(uuid.uuid4())
    new_result.scan_id = new_scan_id
    request.app.state.scan_results[new_scan_id] = new_result
    return new_result.to_response()


@router.post("/scan/{scan_id}/rescan", response_model=ScanResultResponse)
async def rescan(scan_id: str, request: Request):
    """Re-run the demo scan and return a fresh result."""
    if scan_id not in request.app.state.scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")

    new_result = run_demo_scan()
    new_scan_id = str(uuid.uuid4())
    new_result.scan_id = new_scan_id
    request.app.state.scan_results[new_scan_id] = new_result
    return new_result.to_response()
