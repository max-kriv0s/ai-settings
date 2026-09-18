"""Codex-specific sync helpers for ai_settings."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import tomlkit
from config import REPO_ROOT
from contracts import AgentSettings, Hook, Permission, Skill
from json_settings import (
    HOOK_MATCHER,
    hook_event_name,
    merge_hook,
    prune_hooks,
    read_settings,
    write_settings,
)

CODEX_DIR = Path.home() / ".codex"
CODEX_HOOKS_DIR = CODEX_DIR / "hooks"
CODEX_SKILLS_DIR = CODEX_DIR / "skills"
CODEX_AGENTS_FILE = CODEX_DIR / "AGENTS.md"
CODEX_HOOKS_FILE = CODEX_DIR / "hooks.json"
CODEX_CONFIG_FILE = CODEX_DIR / "config.toml"
FILESYSTEM_ACCESS_VALUES = {"deny", "read", "write"}


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
    print(f"{action}: {section} -> codex")
    print(f"  source: {source}")
    print(f"  target: {target}")


def sync_agents_md(settings: AgentSettings, mode: str) -> None:
    agents_md = settings.agentsMD
    if agents_md is None:
        return

    action = symlink_action(agents_md.source_path, CODEX_AGENTS_FILE)
    print_plan(action, "agents", agents_md.source_path, CODEX_AGENTS_FILE)

    if mode == "apply":
        apply_symlink(agents_md.source_path, CODEX_AGENTS_FILE)


def sync_skill(skill: Skill, mode: str) -> None:
    target = CODEX_SKILLS_DIR / skill.skill_id
    action = symlink_action(skill.path, target)
    print_plan(action, f"skill {skill.skill_id}", skill.path, target)

    if mode == "apply":
        apply_symlink(skill.path, target)


def hook_guard_source(hook: Hook) -> Path | None:
    guard = hook.config.get("guard")
    if not isinstance(guard, str):
        return None

    return REPO_ROOT / guard


def registration_extra(hook: Hook) -> dict[str, Any]:
    extra: dict[str, Any] = {}
    timeout = hook.config.get("timeout")
    if isinstance(timeout, int):
        extra["timeout"] = timeout

    status_message = hook.config.get("status_message")
    if isinstance(status_message, str):
        extra["statusMessage"] = status_message

    return extra


def sync_hooks(hooks: list[Hook], mode: str) -> None:
    """Symlink every guard into ~/.codex/hooks/, then register them in ~/.codex/hooks.json.

    Registration lives in hooks.json rather than config.toml: Codex rewrites config.toml
    itself (project trust, plugin state, hook hashes), and stdlib cannot write TOML anyway.

    All guards are written in one pass: they share the file, and pruning needs the full
    picture of what is declared before it can tell a stale entry from a new one.
    """
    settings = read_settings(CODEX_HOOKS_FILE)
    declared: dict[str, set[str]] = {}
    changed = False

    for hook in hooks:
        source = hook_guard_source(hook)
        if source is None:
            continue

        target = CODEX_HOOKS_DIR / Path(source).name
        action = symlink_action(source, target)
        print_plan(action, f"hook {hook.name}", source, target)

        if mode == "apply":
            apply_symlink(source, target)

        event_name = hook_event_name(hook.name, hook.config)
        command = f"python3 {target}"
        declared.setdefault(event_name, set()).add(command)

        action = merge_hook(
            settings, event_name, command, target.name, registration_extra(hook)
        )
        changed = changed or action != "ok"

        print(f"{action}: hook {hook.name} registration -> codex")
        print(f"  target: {CODEX_HOOKS_FILE}")
        print(f"  entry: hooks.{event_name}[matcher={HOOK_MATCHER}] -> {command}")

    for event_name, commands in declared.items():
        for command in prune_hooks(
            settings, event_name, str(CODEX_HOOKS_DIR), commands
        ):
            changed = True
            print(f"remove_hook: {event_name} -> codex")
            print(f"  entry: {command}")

    if mode == "apply" and changed:
        write_settings(CODEX_HOOKS_FILE, settings)


def permission_rules(permissions: list[Permission]) -> dict[str, str]:
    """Map the shared path policy to Codex workspace-root permission rules."""
    rules: dict[str, str] = {}
    for permission in permissions:
        config = permission.config
        for segment in config.get("deny_path_segments", []):
            if isinstance(segment, str):
                rules[f"**/{segment}"] = "deny"
                rules[f"**/{segment}/**"] = "deny"
        for pattern in config.get("deny_file_patterns", []):
            if isinstance(pattern, str):
                rules[f"**/{pattern}"] = "deny"
    return rules


def validate_permission_rules(rules: dict[str, str]) -> None:
    invalid = set(rules.values()) - FILESYSTEM_ACCESS_VALUES
    if invalid:
        raise SyncError(
            "renderer produced an unsupported Codex filesystem access value"
        )


def merge_permissions_document(document: str, permissions: list[Permission]) -> str:
    """Update only managed workspace-root entries of the active permission profile."""
    try:
        parsed = tomlkit.parse(document)
    except tomlkit.exceptions.ParseError as exc:
        raise SyncError(
            f"config.toml is not valid TOML, refusing to touch it: {exc}"
        ) from exc

    profile = parsed.get("default_permissions")
    profiles = parsed.get("permissions")
    if not isinstance(profile, str) or profiles is None:
        raise SyncError("config.toml must define default_permissions and permissions")
    if profile.startswith(":") or profile not in profiles:
        raise SyncError("default_permissions must name an existing custom profile")

    rules = permission_rules(permissions)
    if not rules:
        return document
    validate_permission_rules(rules)

    profile_table = profiles[profile]
    filesystem = profile_table.get("filesystem")
    if filesystem is None or ":workspace_roots" not in filesystem:
        raise SyncError(
            "active permission profile must define filesystem.:workspace_roots"
        )
    workspace = filesystem[":workspace_roots"]
    legacy_keys = {"**/.env*", "**/*.example", "**/*.local"}
    managed_keys = set(rules) | legacy_keys
    for key in managed_keys:
        workspace.pop(key, None)
    for key, access in rules.items():
        workspace[key] = access
    return tomlkit.dumps(parsed)


def backup_config_once(target: Path) -> None:
    backup = target.with_name(f"{target.name}.bak")
    if not backup.exists():
        backup.write_text(target.read_text(encoding="utf-8"), encoding="utf-8")


def write_config_document(document: str) -> None:
    target = (
        CODEX_CONFIG_FILE.resolve()
        if CODEX_CONFIG_FILE.is_symlink()
        else CODEX_CONFIG_FILE
    )
    mode = target.stat().st_mode if target.exists() else None
    backup_config_once(target)
    temp_file = target.with_name(f"{target.name}.tmp")
    temp_file.write_text(document, encoding="utf-8")
    if mode is not None:
        os.chmod(temp_file, mode)
    os.replace(temp_file, target)


def sync_permissions(permissions: list[Permission], mode: str) -> None:
    if not permissions:
        return
    if not CODEX_CONFIG_FILE.exists():
        raise SyncError(
            "Codex config.toml is missing; cannot resolve default_permissions"
        )

    document = CODEX_CONFIG_FILE.read_text(encoding="utf-8")
    updated = merge_permissions_document(document, permissions)
    action = "ok" if updated == document else "update_permissions"
    print(f"{action}: permissions -> codex")
    print(f"  target: {CODEX_CONFIG_FILE}")
    if mode == "apply" and updated != document:
        write_config_document(updated)


def sync(settings: AgentSettings, mode: str) -> None:
    sync_agents_md(settings, mode)

    for skill in settings.skills:
        sync_skill(skill, mode)

    sync_permissions(settings.permissions, mode)
    sync_hooks(settings.hooks, mode)
