"""Shared helpers for hand-edited JSON settings files of AI tools.

Both Claude Code (~/.claude/settings.json) and Codex (~/.codex/hooks.json) keep hook
registration in JSON that a human also edits. The rules are the same for both: never
rewrite the file wholesale, merge by key, back it up once per run, write atomically.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

# Section name in hooks.yaml -> event name understood by the tools. Both use PascalCase.
HOOK_EVENT_NAMES = {
    "pre_tool_use": "PreToolUse",
    "post_tool_use": "PostToolUse",
}

# The guard must see every tool, not just Bash: it also checks paths, written content
# and the working directory.
HOOK_MATCHER = "*"

GUARD_FILE_NAME = "secret_guard.py"

_backed_up: set[Path] = set()


class SettingsError(RuntimeError):
    pass


def read_settings(path: Path) -> dict[str, Any]:
    """Load a settings file; a missing file is an empty document, a broken one is an error."""
    if not path.exists():
        return {}

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SettingsError(
            f"{path.name} is not valid JSON, refusing to touch it: {exc}"
        ) from exc

    if not isinstance(data, dict):
        raise SettingsError(f"{path.name} must contain a JSON object")

    return data


def backup_once(path: Path) -> None:
    """Copy the file next to itself as .bak, once per run, before the first write."""
    if path in _backed_up:
        return

    _backed_up.add(path)
    if path.exists():
        path.with_name(f"{path.name}.bak").write_text(
            path.read_text(encoding="utf-8"), encoding="utf-8"
        )


def write_settings(path: Path, data: dict[str, Any]) -> None:
    backup_once(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    temp_file = path.with_name(f"{path.name}.tmp")
    temp_file.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    os.replace(temp_file, path)


def matcher_block(event_blocks: list[Any]) -> dict[str, Any]:
    """Find the block for our matcher, or create one. Other blocks are left alone."""
    for block in event_blocks:
        if isinstance(block, dict) and block.get("matcher") == HOOK_MATCHER:
            return block

    block: dict[str, Any] = {"matcher": HOOK_MATCHER, "hooks": []}
    event_blocks.append(block)
    return block


def hook_entry(command: str, extra: dict[str, Any]) -> dict[str, Any]:
    return {"type": "command", "command": command, **extra}


def merge_hook(
    settings: dict[str, Any],
    event_name: str,
    command: str,
    extra: dict[str, Any] | None = None,
) -> str:
    """Add or update our guard entry. Returns 'ok', 'update_hook' or 'add_hook'.

    `extra` carries tool-specific registration fields (timeout, statusMessage): they differ
    between Claude Code and Codex, so the caller decides what its tool understands.
    """
    extra = extra or {}
    hooks = settings.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise SettingsError("'hooks' must be an object")

    event_blocks = hooks.setdefault(event_name, [])
    if not isinstance(event_blocks, list):
        raise SettingsError(f"'hooks.{event_name}' must be an array")

    block = matcher_block(event_blocks)
    entries = block.setdefault("hooks", [])
    if not isinstance(entries, list):
        raise SettingsError(f"'hooks.{event_name}[].hooks' must be an array")

    wanted = hook_entry(command, extra)

    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or GUARD_FILE_NAME not in str(
            entry.get("command", "")
        ):
            continue

        if entry == wanted:
            return "ok"

        entries[index] = wanted
        return "update_hook"

    entries.append(wanted)
    return "add_hook"
