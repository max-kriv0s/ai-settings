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

# The guard must see every tool, not just Bash: it also checks paths, written content
# and the working directory.
HOOK_MATCHER = "*"


def hook_event_name(name: str, config: dict[str, Any]) -> str:
    """Each guard names its event in its yaml; the directory it sits in only mirrors it."""
    event = config.get("event")
    if not isinstance(event, str):
        raise SettingsError(f"hook '{name}' must declare a string 'event'")

    return event


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
    """Replace the contents atomically, keeping a symlink a symlink and the mode intact.

    os.replace swaps a directory entry, so writing over a symlink would turn it into a
    plain file — and settings kept in a dotfiles repository are usually symlinked.
    Writing to the resolved target instead leaves the link in place.
    """
    backup_once(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    target = path.resolve() if path.is_symlink() else path
    mode = target.stat().st_mode if target.exists() else None

    temp_file = target.with_name(f"{target.name}.tmp")
    temp_file.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    if mode is not None:
        os.chmod(temp_file, mode)

    os.replace(temp_file, target)


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


def event_entries(settings: dict[str, Any], event_name: str) -> list[Any]:
    hooks = settings.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise SettingsError("'hooks' must be an object")

    event_blocks = hooks.setdefault(event_name, [])
    if not isinstance(event_blocks, list):
        raise SettingsError(f"'hooks.{event_name}' must be an array")

    entries = matcher_block(event_blocks).setdefault("hooks", [])
    if not isinstance(entries, list):
        raise SettingsError(f"'hooks.{event_name}[].hooks' must be an array")

    return entries


def entry_command(entry: Any) -> str:
    return str(entry.get("command", "")) if isinstance(entry, dict) else ""


def merge_hook(
    settings: dict[str, Any],
    event_name: str,
    command: str,
    guard_name: str,
    extra: dict[str, Any] | None = None,
) -> str:
    """Add or update one guard's entry. Returns 'ok', 'update_hook' or 'add_hook'.

    `guard_name` is the guard's file name: several guards now share one event, so an
    entry is recognised by which file it runs, not by being the only one there.

    `extra` carries tool-specific registration fields (timeout, statusMessage): they differ
    between Claude Code and Codex, so the caller decides what its tool understands.
    """
    entries = event_entries(settings, event_name)
    wanted = hook_entry(command, extra or {})

    for index, entry in enumerate(entries):
        if guard_name not in entry_command(entry):
            continue

        if entry == wanted:
            return "ok"

        entries[index] = wanted
        return "update_hook"

    entries.append(wanted)
    return "add_hook"


def prune_hooks(
    settings: dict[str, Any],
    event_name: str,
    owned_prefix: str,
    keep_commands: set[str],
) -> list[str]:
    """Drop our own entries that are no longer declared; foreign ones are never touched.

    Ownership is the path a command runs: everything under `owned_prefix` is ours to
    manage. Without this a guard removed from the YAML would keep running forever.
    """
    entries = event_entries(settings, event_name)
    removed = [
        entry_command(entry)
        for entry in entries
        if owned_prefix in entry_command(entry)
        and entry_command(entry) not in keep_commands
    ]

    if removed:
        entries[:] = [entry for entry in entries if entry_command(entry) not in removed]

    return removed
