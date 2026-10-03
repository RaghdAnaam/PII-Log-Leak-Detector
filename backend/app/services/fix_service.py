"""
Demo fix service.

IMPORTANT: This fix workflow is intentionally limited to the controlled demo project.
It ONLY copies pre-written _fixed/ versions of demo files. It does NOT:
- Execute any uploaded or user-provided code
- Modify arbitrary files on the filesystem
- Apply AI-generated or dynamic patches

This safe, predictable approach is by design for the hackathon demo.
"""

import shutil

from backend.app.models.findings import ScanResult
from backend.app.services.scan_service import DEMO_APP_PATH, run_demo_scan

FIXED_DIR = DEMO_APP_PATH / "_fixed"
DEMO_FILES = ["customer_service.py", "payments.py", "errors.py", "utils.py"]


def apply_demo_fix() -> ScanResult:
    """
    Apply the demo fix by replacing vulnerable demo files with their _fixed/ counterparts.
    Returns a fresh ScanResult after the fix is applied.

    Safety: Only operates on DEMO_APP_PATH. Does not touch any other directory.
    """
    for filename in DEMO_FILES:
        src = FIXED_DIR / filename
        dst = DEMO_APP_PATH / filename
        # Security: only copy files that exist in _fixed/ — never create new files
        # or write outside DEMO_APP_PATH. DEMO_FILES is a hard-coded allowlist;
        # no user-supplied filenames are ever used here.
        if src.exists():
            shutil.copy2(str(src), str(dst))

    # Rescan after fix to produce the updated result.
    # This is the same scan_directory() call used everywhere — no special paths.
    return run_demo_scan()
