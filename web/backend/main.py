from datetime import datetime, timezone
from pathlib import Path
import os
import subprocess
import sys

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware


BACKEND_DIR = Path(__file__).resolve().parent
ROOT_DIR = BACKEND_DIR.parent.parent

if str(BACKEND_DIR) not in sys.path:
    sys.path.append(str(BACKEND_DIR))
if str(ROOT_DIR) not in sys.path:
    sys.path.append(str(ROOT_DIR))

from catalog import get_categories_payload, get_category_by_id, get_tool_by_id, get_tools_payload
from config import get_tools_dir
from os_detect import CURRENT_OS


app = FastAPI(title="Hacking Tool API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _run_backend_action(*args: str) -> dict:
    runner_path = BACKEND_DIR / "runner.py"
    started_at = datetime.now(timezone.utc)
    result = subprocess.run(
        [sys.executable, str(runner_path), *args],
        cwd=str(get_tools_dir()),
        capture_output=True,
        text=True,
        errors="replace",
    )
    finished_at = datetime.now(timezone.utc)

    return {
        "success": result.returncode == 0,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "startedAt": started_at.isoformat(),
        "finishedAt": finished_at.isoformat(),
    }


@app.get("/")
def read_root():
    return {"message": "Welcome to Hacking Tool API"}


@app.get("/api/system")
def get_system():
    return {
        "os": {
            "system": CURRENT_OS.system,
            "distroId": CURRENT_OS.distro_id,
            "distroLike": CURRENT_OS.distro_like,
            "version": CURRENT_OS.distro_version,
            "packageManager": CURRENT_OS.pkg_manager,
            "isRoot": CURRENT_OS.is_root,
            "arch": CURRENT_OS.arch,
            "isWsl": CURRENT_OS.is_wsl,
        },
        "paths": {
            "toolsDir": str(get_tools_dir()),
            "backendDir": str(BACKEND_DIR),
            "repoRoot": str(ROOT_DIR),
        },
        "user": {
            "home": str(Path.home()),
            "name": os.environ.get("USER", os.environ.get("LOGNAME", "")),
        },
    }


@app.get("/api/categories")
def get_categories():
    return get_categories_payload()


@app.get("/api/categories/{category_id}")
def get_category(category_id: int):
    category = get_category_by_id(category_id)
    if category is None:
        raise HTTPException(status_code=404, detail="Category not found")
    return category


@app.post("/api/categories/{category_id}/actions/install-missing")
def install_missing_in_category(category_id: int):
    category = get_category_by_id(category_id)
    if category is None:
        raise HTTPException(status_code=404, detail="Category not found")
    return _run_backend_action("--category-id", str(category_id), "--action", "install-missing")


@app.get("/api/tools")
def get_tools():
    return get_tools_payload()


@app.get("/api/tools/{tool_id}")
def get_tool(tool_id: int):
    tool = get_tool_by_id(tool_id)
    if tool is None:
        raise HTTPException(status_code=404, detail="Tool not found")
    return tool


@app.post("/api/tools/{tool_id}/actions/{action_name}")
def run_tool_action(tool_id: int, action_name: str):
    tool = get_tool_by_id(tool_id)
    if tool is None:
        raise HTTPException(status_code=404, detail="Tool not found")

    if action_name not in {"install", "update", "uninstall", "run"}:
        raise HTTPException(status_code=400, detail="Unsupported action")

    return _run_backend_action("--tool-id", str(tool_id), "--action", action_name)


@app.post("/api/tools/{tool_id}/options/{option_index}")
def run_tool_option(tool_id: int, option_index: int):
    tool = get_tool_by_id(tool_id)
    if tool is None:
        raise HTTPException(status_code=404, detail="Tool not found")

    return _run_backend_action("--tool-id", str(tool_id), "--option-index", str(option_index))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
