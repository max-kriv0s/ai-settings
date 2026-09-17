"""Codex-specific sync helpers for ai_settings."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from config import REPO_ROOT
from contracts import AgentSettings, AgentsMD, Hook, Skill
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


def sync(settings: AgentSettings, mode: str) -> None:
    sync_agents_md(settings, mode)

    for skill in settings.skills:
        sync_skill(skill, mode)

    sync_hooks(settings.hooks, mode)
