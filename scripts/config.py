"""Paths and script registry for ai_settings sync."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

# scripts/ lives in the repository root, so both point at the same place. REPO_ROOT is
# kept as a separate name because `guard` paths in YAML are resolved against it.
ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT

CONFIG_FILES = {
    "skills": ROOT / "skills" / "skills.yaml",
    "permissions": ROOT / "permissions" / "policy.yaml",
    # Hooks are not here: each guard keeps its own yaml, see hook_config_files().
    "mcp": ROOT / "mcp" / "profiles.yaml",
    "plugins": ROOT / "plugins" / "policy.yaml",
}

# Shared fragments pulled into a section by `include: <name>`.
SHARED_FILES = {
    "secrets": ROOT / "shared" / "sensitive-artifacts.yaml",
    "interpreters": ROOT / "shared" / "interpreters.yaml",
    "read_commands": ROOT / "shared" / "read-commands.yaml",
    "command_syntax": ROOT / "shared" / "command-syntax.yaml",
}

# Each guard keeps its own yaml next to itself, grouped by event: hooks/<Event>/<name>/.
HOOKS_DIR = ROOT / "hooks"


def hook_config_files() -> list[Path]:
    return sorted(HOOKS_DIR.rglob("*.yaml"))


INCLUDE_KEY = "include"

SYNC_CONFIG = ROOT / "scripts" / "sync.yaml"


def read_shared(name: str) -> dict[str, Any]:
    path = SHARED_FILES.get(name)
    if path is None:
        raise KeyError(f"unknown shared fragment: {name}")

    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def resolve_includes(value: Any) -> Any:
    """Replace `include: <name>` with the shared fragment. Keys set locally win."""
    if isinstance(value, list):
        return [resolve_includes(item) for item in value]

    if not isinstance(value, dict):
        return value

    resolved = {
        key: resolve_includes(item) for key, item in value.items() if key != INCLUDE_KEY
    }

    name = value.get(INCLUDE_KEY)
    if not isinstance(name, str):
        return resolved

    merged = dict(read_shared(name))
    merged.update(resolved)
    return merged


TOOL_SCRIPTS = {
    "codex": Path("tools/codex.py"),
    "claude": Path("tools/claude.py"),
    "zed": Path("tools/zed.py"),
    "pi": Path("tools/pi.py"),
}
