import sys
from pathlib import Path

import pytest
from starlette.testclient import TestClient

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from backend.app.main import app


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c

@pytest.fixture
def demo_app_path():
    return Path(__file__).parent.parent.parent / "demo_vulnerable_app"
