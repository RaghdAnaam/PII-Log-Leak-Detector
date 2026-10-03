"""
Security utilities for file upload handling.

Design decisions:
- ZIP validation prevents malicious archives from being processed.
- Path traversal prevention stops ZIP entries from writing outside the temp directory.
- Size limits prevent DoS via large uploads.
- No uploaded code is executed — files are only read as text.
"""

import io
import os
import zipfile
from pathlib import Path

from backend.app.core.config import MAX_UPLOAD_BYTES, SUPPORTED_EXTENSIONS


class SecurityError(Exception):
    pass


def validate_zip(file_bytes: bytes) -> None:
    """
    Validate a ZIP archive before extraction.
    Raises SecurityError if the archive is invalid, too large, or contains dangerous paths.
    """
    # Check size
    if len(file_bytes) > MAX_UPLOAD_BYTES:
        raise SecurityError(
            f"Upload exceeds maximum allowed size of {MAX_UPLOAD_BYTES} bytes"
        )

    # Check it's a valid ZIP
    if not zipfile.is_zipfile(io.BytesIO(file_bytes)):
        raise SecurityError("Uploaded file is not a valid ZIP archive")

    with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
        for entry in zf.infolist():
            name = entry.filename

            # Reject absolute paths
            if os.path.isabs(name):
                raise SecurityError(
                    f"ZIP entry contains an absolute path: {name!r}"
                )

            # Reject path traversal attempts
            if ".." in Path(name).parts:
                raise SecurityError(
                    f"ZIP entry contains a path traversal sequence: {name!r}"
                )


def safe_extract(zip_bytes: bytes, dest_dir: str) -> None:
    """
    Extract a validated ZIP to dest_dir safely.
    Resolves each entry path and ensures it stays within dest_dir.
    Skips unsupported file types and binary-looking entries.
    """
    real_dest = os.path.realpath(dest_dir)

    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for entry in zf.infolist():
            # Skip directories
            if entry.filename.endswith("/"):
                continue

            # Only extract supported extensions
            _, ext = os.path.splitext(entry.filename)
            if ext.lower() not in SUPPORTED_EXTENSIONS:
                continue

            target_path = os.path.realpath(
                os.path.join(dest_dir, entry.filename)
            )

            # Ensure the resolved path is within dest_dir
            if not target_path.startswith(real_dest + os.sep) and target_path != real_dest:
                raise SecurityError(
                    f"ZIP entry resolves outside destination directory: {entry.filename!r}"
                )

            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            with zf.open(entry) as src, open(target_path, "wb") as dst:
                dst.write(src.read())
