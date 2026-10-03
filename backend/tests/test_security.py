"""
Tests for security utilities: validate_zip and safe_extract.
"""
import io
import os
import tempfile
import zipfile

import pytest

from backend.app.core.config import MAX_UPLOAD_BYTES
from backend.app.core.security import SecurityError, safe_extract, validate_zip


def make_zip(entries: dict) -> bytes:
    """Helper: create an in-memory ZIP with given filename→content entries."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return buf.getvalue()


def test_valid_zip_passes():
    data = make_zip({"main.py": "x = 1"})
    validate_zip(data)  # Should not raise


def test_oversized_zip_rejected():
    data = b"x" * (MAX_UPLOAD_BYTES + 1)
    with pytest.raises(SecurityError, match="exceeds maximum"):
        validate_zip(data)


def test_path_traversal_rejected():
    data = make_zip({"../../etc/passwd": "root:x:0:0"})
    with pytest.raises(SecurityError):
        validate_zip(data)


def test_absolute_path_rejected():
    data = make_zip({"/etc/passwd": "root:x:0:0"})
    with pytest.raises(SecurityError):
        validate_zip(data)


def test_invalid_zip_rejected():
    """Non-ZIP bytes should raise SecurityError."""
    with pytest.raises(SecurityError):
        validate_zip(b"this is not a zip file")


def test_safe_extract_stays_in_dest():
    """Extracted files must stay within dest_dir."""
    data = make_zip({"subdir/main.py": "x = 1", "utils.py": "y = 2"})
    with tempfile.TemporaryDirectory() as tmpdir:
        safe_extract(data, tmpdir)
        extracted = []
        for root, _, files in os.walk(tmpdir):
            for f in files:
                extracted.append(os.path.join(root, f))
        assert len(extracted) == 2
        for path in extracted:
            assert os.path.realpath(path).startswith(os.path.realpath(tmpdir))


def test_safe_extract_skips_unsupported_extensions():
    """Files with unsupported extensions must not be extracted."""
    data = make_zip({
        "main.py": "x = 1",          # supported
        "readme.md": "# hello",       # NOT in SUPPORTED_EXTENSIONS
        "binary.exe": "MZ\x90",       # NOT supported
    })
    with tempfile.TemporaryDirectory() as tmpdir:
        safe_extract(data, tmpdir)
        extracted = [
            f for root, _, files in os.walk(tmpdir) for f in files
        ]
        assert "main.py" in extracted
        assert "readme.md" not in extracted
        assert "binary.exe" not in extracted


def test_safe_extract_skips_directories():
    """Directory entries (trailing slash) must be skipped silently."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.mkdir("subdir")           # directory entry
        zf.writestr("subdir/main.py", "x = 1")
    data = buf.getvalue()
    with tempfile.TemporaryDirectory() as tmpdir:
        safe_extract(data, tmpdir)   # Should not raise
