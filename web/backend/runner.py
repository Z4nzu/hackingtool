import argparse
import os
import sys
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parent
ROOT_DIR = BACKEND_DIR.parent.parent

if str(BACKEND_DIR) not in sys.path:
    sys.path.append(str(BACKEND_DIR))
if str(ROOT_DIR) not in sys.path:
    sys.path.append(str(ROOT_DIR))

from catalog import resolve_category_collection, resolve_tool_instance
from config import get_tools_dir


def _run_tool_action(tool_id: int, action: str, option_index: int | None) -> int:
    tool, _category = resolve_tool_instance(tool_id)
    if tool is None:
        print(f"Tool {tool_id} not found.", file=sys.stderr)
        return 2

    os.chdir(str(get_tools_dir()))

    if option_index is not None:
        if option_index < 0 or option_index >= len(tool.OPTIONS):
            print(f"Option {option_index} not found for tool {tool_id}.", file=sys.stderr)
            return 2
        label, callback = tool.OPTIONS[option_index]
        print(f"==> {tool.TITLE} :: {label}")
        callback()
        return 0

    actions = {
        "install": tool.install,
        "update": tool.update,
        "uninstall": tool.uninstall,
        "run": tool.run,
    }

    if action not in actions:
        print(f"Unsupported action: {action}", file=sys.stderr)
        return 2

    print(f"==> {tool.TITLE} :: {action}")
    actions[action]()
    return 0


def _run_category_action(category_id: int, action: str) -> int:
    _collection, category = resolve_category_collection(category_id)
    if _collection is None:
        print(f"Category {category_id} not found.", file=sys.stderr)
        return 2

    os.chdir(str(get_tools_dir()))

    if action != "install-missing":
        print(f"Unsupported category action: {action}", file=sys.stderr)
        return 2

    pending_tools = [
        tool for tool, _leaf_title, _top_title in category["flattenedTools"]
        if not getattr(tool, "ARCHIVED", False)
        and hasattr(tool, "is_installed")
        and tool.is_installed is False
    ]
    print(f"==> {category['label']} :: install-missing ({len(pending_tools)} tools)")

    for index, tool in enumerate(pending_tools, start=1):
        print(f"\n[{index}/{len(pending_tools)}] {tool.TITLE}")
        tool.install()

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Hacking Tool backend actions.")
    parser.add_argument("--tool-id", type=int)
    parser.add_argument("--category-id", type=int)
    parser.add_argument("--action", type=str)
    parser.add_argument("--option-index", type=int)
    args = parser.parse_args()

    if args.tool_id:
        return _run_tool_action(args.tool_id, args.action or "", args.option_index)
    if args.category_id:
        return _run_category_action(args.category_id, args.action or "")

    print("Either --tool-id or --category-id is required.", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
