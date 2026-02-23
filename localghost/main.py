"""Localghost entry point — run with: uv run python -m backend.main"""

import uvicorn

from backend.main import LOCALGHOST_PORT

if __name__ == "__main__":
    uvicorn.run("backend.main:app", host="127.0.0.1", port=LOCALGHOST_PORT, reload=True)
