import uuid

from fastapi import APIRouter, HTTPException, Request

from backend.app.models.findings import ScanResultResponse
from backend.app.services.fix_service import apply_demo_fix
from backend.app.services.scan_service import run_demo_scan

router = APIRouter(prefix="/api")


@router.post("/scan/demo", response_model=ScanResultResponse)
async def scan_demo(request: Request):
    """
    Scan the demo vulnerable app. Returns masked findings only.
    matched_value is never included in the response (enforced by ScanResultResponse model).
    """
    result = run_demo_scan()
    # Assign a scan_id and store in app state for subsequent fix/rescan calls
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
    Only works for demo scans — does not modify arbitrary files.
    """
    if scan_id not in request.app.state.scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Apply fix and get fresh scan result
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
