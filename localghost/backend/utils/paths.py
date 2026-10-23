"""Resource and writable data locations for source and installed applications."""

import os
import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[2]
SOURCE_CHECKOUT = (PROJECT_DIR / "pyproject.toml").is_file()


def data_path(filename: str) -> Path:
    if SOURCE_CHECKOUT:
        return PROJECT_DIR / filename
    base = os.environ.get("XDG_DATA_HOME")
    if not base:
        base = os.environ.get("LOCALAPPDATA") if sys.platform == "win32" else None
    return Path(base or Path.home() / ".local" / "share") / "localghost" / filename
