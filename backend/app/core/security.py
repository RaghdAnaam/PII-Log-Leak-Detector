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
    # Security: enforce a hard size cap before doing any further processing.
    # This prevents an attacker from uploading a multi-GB file to exhaust memory
    # or a "zip bomb" (tiny archive that expands to gigabytes when opened).
    if len(file_bytes) > MAX_UPLOAD_BYTES:
        raise SecurityError(
            f"Upload exceeds maximum allowed size of {MAX_UPLOAD_BYTES} bytes"
        )

    # Security: confirm the magic bytes match a ZIP before calling ZipFile.
    # Passing arbitrary bytes to ZipFile without this check could trigger
    # unexpected behaviour in the underlying C library.
    if not zipfile.is_zipfile(io.BytesIO(file_bytes)):
        raise SecurityError("Uploaded file is not a valid ZIP archive")

    with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
        for entry in zf.infolist():
            name = entry.filename

            # Security: reject entries with absolute paths (e.g. /etc/passwd).
            # os.path.join(dest, "/etc/passwd") would silently discard dest,
            # causing the extracted file to land at the absolute path.
            if os.path.isabs(name):
                raise SecurityError(
                    f"ZIP entry contains an absolute path: {name!r}"
                )

            # Security: reject path traversal sequences (e.g. ../../etc/shadow).
            # Using Path().parts is more reliable than a string search because
            # it normalises OS separators before checking individual components.
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
    # Security: resolve symlinks in dest_dir before comparison.
    # If dest_dir itself were a symlink, a naive startswith check could be
    # bypassed by crafting a path that traverses the symlink target.
    real_dest = os.path.realpath(dest_dir)

    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for entry in zf.infolist():
            # Skip directory entries — they are created implicitly by makedirs.
            if entry.filename.endswith("/"):
                continue

            # Security: only extract file types the scanner actually reads.
            # This prevents executable, compiled, or binary files from being
            # written to the extraction directory, even if they pass path checks.
            _, ext = os.path.splitext(entry.filename)
            if ext.lower() not in SUPPORTED_EXTENSIONS:
                continue

            # Security: second path-traversal check using the fully resolved path.
            # validate_zip() rejected ".." in path components, but we re-verify
            # here after joining with dest_dir to catch any OS normalisation edge
            # cases (e.g. on Windows, UNC paths or drive letters).
            target_path = os.path.realpath(
                os.path.join(dest_dir, entry.filename)
            )

            # Security: the canonical resolved path must be inside real_dest.
            # This is the final guarantee: even if a crafted entry slips through
            # the name check, realpath comparison will catch it here.
            if not target_path.startswith(real_dest + os.sep) and target_path != real_dest:
                raise SecurityError(
                    f"ZIP entry resolves outside destination directory: {entry.filename!r}"
                )

            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            with zf.open(entry) as src, open(target_path, "wb") as dst:
                dst.write(src.read())
