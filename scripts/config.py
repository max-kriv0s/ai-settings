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

SHARED_DIR = ROOT / "shared"

# Each guard keeps its own yaml next to itself, grouped by event: hooks/<Event>/<name>/.
HOOKS_DIR = ROOT / "hooks"


def hook_config_files() -> list[Path]:
    return sorted(HOOKS_DIR.rglob("*.yaml"))


INCLUDE_KEY = "include"

SYNC_CONFIG = ROOT / "scripts" / "sync.yaml"


def read_shared(location: str) -> dict[str, Any]:
    """Read a shared fragment by its path, relative to the repository root.

    The path is written out in full in the yaml, so what gets included is visible where
    it is used — no registry of short names to look up and no way for a name and a file
    to drift apart. Leaving the repository is refused: an include is our own file.
    """
    path = (ROOT / location).resolve()
    if not path.is_relative_to(SHARED_DIR):
        raise ValueError(f"include must point inside shared/: {location}")

    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def resolve_includes(value: Any) -> Any:
    """Replace `include: <path>` with the shared fragment. Keys set locally win."""
    if isinstance(value, list):
        return [resolve_includes(item) for item in value]

    if not isinstance(value, dict):
        return value

    resolved = {
        key: resolve_includes(item) for key, item in value.items() if key != INCLUDE_KEY
    }

    location = value.get(INCLUDE_KEY)
    if not isinstance(location, str):
        return resolved

    merged = dict(read_shared(location))
    merged.update(resolved)
    return merged


TOOL_SCRIPTS = {
    "codex": Path("tools/codex.py"),
    "claude": Path("tools/claude.py"),
    "zed": Path("tools/zed.py"),
    "pi": Path("tools/pi.py"),
}
