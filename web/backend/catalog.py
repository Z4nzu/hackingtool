import os
import sys
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parent
ROOT_DIR = BACKEND_DIR.parent.parent

if str(ROOT_DIR) not in sys.path:
    sys.path.append(str(ROOT_DIR))

from config import get_tools_dir
from core import HackingTool as ODKTool, HackingToolsCollection as ODKToolsCollection
from hackingtool import all_tools, tool_definitions
from os_detect import CURRENT_OS


def _walk_collection(items: list, leaf_title: str = "", top_level_title: str = "") -> list[tuple[ODKTool, str, str]]:
    flattened: list[tuple[ODKTool, str, str]] = []
    for item in items:
        if isinstance(item, ODKToolsCollection):
            next_leaf = item.TITLE or leaf_title
            next_top_level = top_level_title or next_leaf
            flattened.extend(_walk_collection(item.TOOLS, next_leaf, next_top_level))
        elif isinstance(item, ODKTool):
            flattened.append((item, leaf_title or top_level_title, top_level_title or leaf_title))
    return flattened


def _tool_support_reason(tool: ODKTool) -> str | None:
    if getattr(tool, "ARCHIVED", False):
        return getattr(tool, "ARCHIVED_REASON", "") or "Archived"
    supported_os = getattr(tool, "SUPPORTED_OS", ["linux", "macos"])
    if CURRENT_OS.system not in supported_os:
        supported = ", ".join(supported_os)
        return f"Unsupported on {CURRENT_OS.system}. Supported: {supported}."
    return None


def _tool_local_path(tool: ODKTool) -> str | None:
    original_cwd = os.getcwd()
    try:
        os.chdir(str(get_tools_dir()))
        return tool._get_tool_dir()
    finally:
        os.chdir(original_cwd)


def _option_dict(tool: ODKTool, index: int, option: tuple[str, object]) -> dict:
    label, callback = option
    callback_name = getattr(callback, "__name__", "")

    web_supported = False
    kind = "custom"

    if label == "Install":
        kind = "install"
        web_supported = True
    elif label == "Update":
        kind = "update"
        web_supported = True
    elif label == "Uninstall":
        kind = "uninstall"
        web_supported = tool.__class__.uninstall is ODKTool.uninstall and bool(getattr(tool, "UNINSTALL_COMMANDS", []))
    elif label == "Run":
        kind = "run"
        web_supported = tool.__class__.run is ODKTool.run and bool(getattr(tool, "RUN_COMMANDS", []))
    elif label == "Open Folder":
        kind = "open-folder"
    elif label == "Update System":
        kind = "update-system"
        web_supported = True
    elif label == "Update Hacking Tool":
        kind = "update-hackingtool"
        web_supported = True
    elif callback_name == "open":
        kind = "open"

    return {
        "index": index,
        "label": label,
        "kind": kind,
        "webSupported": web_supported,
    }


def _tool_to_dict(
    tool_id: int,
    tool: ODKTool,
    category_id: int,
    category_title: str,
    category_label: str,
    category_icon: str,
    top_level_category_title: str,
) -> dict:
    local_path = _tool_local_path(tool)
    support_reason = _tool_support_reason(tool)
    compatible = support_reason is None
    options = [_option_dict(tool, index, option) for index, option in enumerate(tool.OPTIONS)]

    return {
        "id": tool_id,
        "title": tool.TITLE,
        "description": getattr(tool, "DESCRIPTION", "") or "",
        "categoryId": category_id,
        "category": category_title,
        "categoryLabel": category_label,
        "categoryIcon": category_icon,
        "topLevelCategory": top_level_category_title,
        "tags": getattr(tool, "TAGS", []),
        "installed": tool.is_installed if hasattr(tool, "is_installed") else False,
        "projectUrl": getattr(tool, "PROJECT_URL", "") or "",
        "localPath": local_path,
        "supportedOs": getattr(tool, "SUPPORTED_OS", ["linux", "macos"]),
        "compatible": compatible,
        "supportReason": support_reason,
        "archived": getattr(tool, "ARCHIVED", False),
        "archivedReason": getattr(tool, "ARCHIVED_REASON", "") or "",
        "requires": {
            "root": getattr(tool, "REQUIRES_ROOT", False),
            "wifi": getattr(tool, "REQUIRES_WIFI", False),
            "go": getattr(tool, "REQUIRES_GO", False),
            "ruby": getattr(tool, "REQUIRES_RUBY", False),
            "java": getattr(tool, "REQUIRES_JAVA", False),
            "docker": getattr(tool, "REQUIRES_DOCKER", False),
        },
        "commands": {
            "install": getattr(tool, "INSTALL_COMMANDS", []),
            "uninstall": getattr(tool, "UNINSTALL_COMMANDS", []),
            "run": getattr(tool, "RUN_COMMANDS", []),
        },
        "options": options,
        "actions": {
            "canInstall": any(option["kind"] == "install" and option["webSupported"] for option in options),
            "canUpdate": any(option["kind"] == "update" and option["webSupported"] for option in options),
            "canUninstall": any(option["kind"] == "uninstall" and option["webSupported"] for option in options),
            "canRun": any(option["kind"] == "run" and option["webSupported"] for option in options),
        },
    }


def get_category_collections() -> list[dict]:
    categories = []
    for index, ((full_title, icon, menu_label), collection) in enumerate(zip(tool_definitions, all_tools), start=1):
        flattened_tools = _walk_collection(collection.TOOLS, full_title, full_title)
        active_tools = [tool for tool, _leaf, _top in flattened_tools if _tool_support_reason(tool) is None]
        archived_tools = [tool for tool, _leaf, _top in flattened_tools if getattr(tool, "ARCHIVED", False)]
        incompatible_tools = [
            tool for tool, _leaf, _top in flattened_tools
            if not getattr(tool, "ARCHIVED", False)
            and CURRENT_OS.system not in getattr(tool, "SUPPORTED_OS", ["linux", "macos"])
        ]
        categories.append({
            "id": index,
            "title": full_title,
            "label": menu_label,
            "icon": icon,
            "description": getattr(collection, "DESCRIPTION", "") or "",
            "counts": {
                "active": len(active_tools),
                "archived": len(archived_tools),
                "incompatible": len(incompatible_tools),
                "installed": len([tool for tool in active_tools if getattr(tool, "is_installed", False)]),
                "total": len(flattened_tools),
            },
            "supportsInstallAll": any(hasattr(tool, "is_installed") and not getattr(tool, "ARCHIVED", False) for tool in active_tools),
            "collection": collection,
            "flattenedTools": flattened_tools,
        })
    return categories


def get_categories_payload() -> list[dict]:
    categories = []
    for category in get_category_collections():
        categories.append({key: value for key, value in category.items() if key not in {"collection", "flattenedTools"}})
    return categories


def get_tools_payload() -> list[dict]:
    tools = []
    tool_id = 1

    for category in get_category_collections():
        for tool, leaf_title, top_level_title in category["flattenedTools"]:
            tools.append(_tool_to_dict(
                tool_id=tool_id,
                tool=tool,
                category_id=category["id"],
                category_title=leaf_title,
                category_label=category["label"],
                category_icon=category["icon"],
                top_level_category_title=top_level_title,
            ))
            tool_id += 1

    return tools


def get_tool_by_id(tool_id: int) -> dict | None:
    for tool in get_tools_payload():
        if tool["id"] == tool_id:
            return tool
    return None


def get_category_by_id(category_id: int) -> dict | None:
    for category in get_categories_payload():
        if category["id"] == category_id:
            return category
    return None


def resolve_tool_instance(tool_id: int) -> tuple[ODKTool, dict] | tuple[None, None]:
    current_id = 1
    for category in get_category_collections():
        for tool, _leaf_title, _top_level_title in category["flattenedTools"]:
            if current_id == tool_id:
                return tool, category
            current_id += 1
    return None, None


def resolve_category_collection(category_id: int) -> tuple[ODKToolsCollection, dict] | tuple[None, None]:
    for category in get_category_collections():
        if category["id"] == category_id:
            return category["collection"], category
    return None, None
