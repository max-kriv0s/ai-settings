"""Claude Code-specific sync helpers for ai_settings."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from config import REPO_ROOT
from contracts import AgentSettings, Hook, Mcp, Permission, Plugin, Skill
from json_settings import (
    HOOK_EVENT_NAMES,
    HOOK_MATCHER,
    merge_hook,
    read_settings,
    write_settings,
)

CLAUDE_DIR = Path.home() / ".claude"
CLAUDE_AGENTS_FILE = CLAUDE_DIR / "CLAUDE.md"
CLAUDE_SKILLS_DIR = CLAUDE_DIR / "skills"
CLAUDE_SETTINGS_FILE = CLAUDE_DIR / "settings.json"

PERMISSION_TOOLS = ("Read", "Edit")


class SyncError(RuntimeError):
    pass


def symlink_action(source: Path, target: Path) -> str:
    if target.is_symlink():
        current = Path(os.readlink(target))
        if current == source:
            return "ok"

        return "replace_wrong_symlink"

    if target.exists():
        return "blocked_existing_path"

    return "create_symlink"


def apply_symlink(source: Path, target: Path) -> None:
    action = symlink_action(source, target)
    if action == "ok":
        return

    if action == "blocked_existing_path":
        raise SyncError(f"refusing to replace non-symlink path: {target}")

    target.parent.mkdir(parents=True, exist_ok=True)
    if action == "replace_wrong_symlink":
        target.unlink()

    target.symlink_to(source)


def print_plan(action: str, section: str, source: Path, target: Path) -> None:
    print(f"{action}: {section} -> claude")
    print(f"  source: {source}")
    print(f"  target: {target}")


def sync_agents_md(settings: AgentSettings, mode: str) -> None:
    agents_md = settings.agentsMD
    if agents_md is None:
        return

    action = symlink_action(agents_md.source_path, CLAUDE_AGENTS_FILE)
    print_plan(action, "agents", agents_md.source_path, CLAUDE_AGENTS_FILE)

    if mode == "apply":
        apply_symlink(agents_md.source_path, CLAUDE_AGENTS_FILE)


def sync_skill(skill: Skill, mode: str) -> None:
    target = CLAUDE_SKILLS_DIR / skill.skill_id
    action = symlink_action(skill.path, target)
    print_plan(action, f"skill {skill.skill_id}", skill.path, target)

    if mode == "apply":
        apply_symlink(skill.path, target)


def hook_guard_source(hook: Hook) -> Path | None:
    guard = hook.config.get("guard")
    if not isinstance(guard, str):
        return None

    return REPO_ROOT / guard


def sync_hook(hook: Hook, mode: str) -> None:
    guard_path = hook_guard_source(hook)
    if guard_path is None:
        return

    event_name = HOOK_EVENT_NAMES.get(hook.name, hook.name)
    command = f"python3 {guard_path}"

    # `timeout` and `status_message` from hooks.yaml are Codex registration fields;
    # support for them in Claude Code is unconfirmed, so nothing extra is written here.
    settings = read_settings(CLAUDE_SETTINGS_FILE)
    action = merge_hook(settings, event_name, command)

    print(f"{action}: hook {hook.name} -> claude")
    print(f"  target: {CLAUDE_SETTINGS_FILE}")
    print(f"  entry: hooks.{event_name}[matcher={HOOK_MATCHER}] -> {command}")

    if mode == "apply" and action != "ok":
        write_settings(CLAUDE_SETTINGS_FILE, settings)


def derive_deny_patterns(permission: Permission) -> list[str]:
    config = permission.config
    segments = config.get("deny_path_segments") or []
    file_patterns = config.get("deny_file_patterns") or []

    patterns: list[str] = [f"**/{segment}/**" for segment in segments]
    patterns.extend(file_patterns)
    return patterns


def derive_ask_entries(permission: Permission) -> list[str]:
    """Commands the hook lets through but a human should confirm, e.g. `git commit`."""
    ask_commands = permission.config.get("ask_commands") or []
    return [f"Bash({command})" for command in ask_commands if isinstance(command, str)]


def merge_permission_list(
    settings: dict[str, Any], key: str, entries: list[str]
) -> list[str]:
    """Append missing entries to permissions.<key>. Existing ones are never removed."""
    permissions = settings.setdefault("permissions", {})
    if not isinstance(permissions, dict):
        raise SyncError("settings.json: 'permissions' must be an object")

    current = permissions.setdefault(key, [])
    if not isinstance(current, list):
        raise SyncError(f"settings.json: 'permissions.{key}' must be an array")

    added = [entry for entry in entries if entry not in current]
    current.extend(added)
    return added


def sync_permission(permission: Permission, mode: str) -> None:
    deny_entries = [
        f"{tool}({pattern})"
        for pattern in derive_deny_patterns(permission)
        for tool in PERMISSION_TOOLS
    ]
    ask_entries = derive_ask_entries(permission)

    if not deny_entries and not ask_entries:
        print(f"not_implemented: permission {permission.name} -> claude")
        print(
            "  reason: no deny_path_segments/deny_file_patterns/ask_commands in this section"
        )
        return

    settings = read_settings(CLAUDE_SETTINGS_FILE)
    added_deny = merge_permission_list(settings, "deny", deny_entries)
    added_ask = merge_permission_list(settings, "ask", ask_entries)

    action = "ok" if not added_deny and not added_ask else "add_permissions"
    print(f"{action}: permission {permission.name} -> claude")
    print(f"  target: {CLAUDE_SETTINGS_FILE}")

    for entry in added_deny:
        print(f"  + deny: {entry}")

    for entry in added_ask:
        print(f"  + ask: {entry}")

    if mode == "apply" and action != "ok":
        write_settings(CLAUDE_SETTINGS_FILE, settings)


def sync_mcp(mcp: Mcp, mode: str) -> None:
    print(f"not_implemented: mcp {mcp.name} -> claude")
    print("  reason: ai_settings/mcp/profiles.yaml has no MCP profiles defined yet")


def sync_plugin(plugin: Plugin, mode: str) -> None:
    print(f"not_implemented: plugin {plugin.name} -> claude")
    print("  reason: ai_settings/plugins/policy.yaml has no trust rules defined yet")


def sync(settings: AgentSettings, mode: str) -> None:
    sync_agents_md(settings, mode)

    for skill in settings.skills:
        sync_skill(skill, mode)

    synced_hooks = set()
    for hook in settings.hooks:
        guard_path = hook_guard_source(hook)
        if guard_path is None or hook.name in synced_hooks:
            continue

        synced_hooks.add(hook.name)
        sync_hook(hook, mode)

    for permission in settings.permissions:
        sync_permission(permission, mode)

    for mcp in settings.mcp:
        sync_mcp(mcp, mode)

    for plugin in settings.plugins:
        sync_plugin(plugin, mode)
