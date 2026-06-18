import pytest
import sys

from pathlib import Path

@pytest.fixture
def hooker_path():
    return [sys.executable, str(Path(__file__).parent.parent / "src" / "hooker" / "main.py") ]
