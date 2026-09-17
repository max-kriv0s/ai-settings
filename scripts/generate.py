"""Generate managed code blocks from ai_settings YAML files."""

from __future__ import annotations

import difflib
import pprint
import sys
from pathlib import Path
from typing import Any

import yaml
from config import REPO_ROOT, hook_config_files, resolve_includes

BEGIN_MARKER = "# BEGIN AI_SETTINGS GENERATED"
END_MARKER = "# END AI_SETTINGS GENERATED"
MODES = ("plan", "apply")
PREVIEW_SUFFIX = ".test_generated"


class GenerateError(RuntimeError):
    pass


def read_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    if data is None:
        return {}

    if not isinstance(data, dict):
        raise GenerateError(f"expected mapping in YAML config: {path}")

    return resolve_includes(data)


def clean_section(section: dict[str, Any]) -> dict[str, Any]:
    """Drop registration-only keys: the guard never reads them, the sync adapters do."""
    result = dict(section)
    for key in (
        "enabled",
        "tools",
        "guard",
        "event",
        "matcher",
        "timeout",
        "status_message",
    ):
        result.pop(key, None)

    return result


def validate_hooks_config(config: dict[str, Any], config_path: Path) -> None:
    for hook_name, hook_config in config.items():
        if hook_name == "meta":
            continue

        if not isinstance(hook_config, dict):
            raise GenerateError(f"hook config must be a mapping: {config_path}")

        if not isinstance(hook_config.get("guard"), str):
            raise GenerateError(
                f"hook config must contain string 'guard': {config_path}"
            )


def build_generated_content(path: Path, settings: dict[str, Any]) -> str:
    """Return the guard file content with the generated block replaced."""
    content = path.read_text(encoding="utf-8")
    begin_count = content.count(BEGIN_MARKER)
    end_count = content.count(END_MARKER)

    if begin_count != 1 or end_count != 1:
        raise GenerateError(f"expected exactly one generated block in: {path}")

    begin_index = content.find(BEGIN_MARKER)
    end_index = content.find(END_MARKER)
    if end_index < begin_index:
        raise GenerateError(f"generated block markers are out of order in: {path}")

    block = pprint.pformat(settings, width=100, sort_dicts=False)
    generated = (
        f"{BEGIN_MARKER}\nGUARD_SETTINGS: dict[str, Any] = {block}\n{END_MARKER}"
    )
    end_index += len(END_MARKER)
    return content[:begin_index] + generated + content[end_index:]


def preview_path(path: Path) -> Path:
    return path.with_name(f"{path.stem}{PREVIEW_SUFFIX}{path.suffix}")


def print_diff(path: Path, content: str) -> None:
    current = path.read_text(encoding="utf-8")
    diff = difflib.unified_diff(
        current.splitlines(keepends=True),
        content.splitlines(keepends=True),
        fromfile=f"{path.name} (current)",
        tofile=f"{path.name} (generated)",
    )
    lines = list(diff)

    if not lines:
        print(f"no changes: {path.name}")
        return

    sys.stdout.writelines(lines)


def read_mode(argv: list[str]) -> str:
    if not argv:
        return "apply"

    mode = argv[0]
    if mode not in MODES:
        raise GenerateError(f"unknown mode: {mode}; expected one of {', '.join(MODES)}")

    return mode


def main(argv: list[str]) -> int:
    mode = read_mode(argv)
    settings_by_guard: dict[str, dict[str, Any]] = {}

    # Every yaml under hooks/ describes one guard; a guard gets only its own section.
    for config_path in hook_config_files():
        hooks_config = read_yaml(config_path)
        validate_hooks_config(hooks_config, config_path)

        for hook_name, hook_config in hooks_config.items():
            if hook_name == "meta":
                continue

            guard = hook_config["guard"]
            guard_settings = settings_by_guard.setdefault(guard, {})
            guard_settings[hook_name] = clean_section(hook_config)

    for guard, settings in settings_by_guard.items():
        guard_path = REPO_ROOT / guard
        content = build_generated_content(guard_path, settings)

        if mode == "plan":
            print_diff(guard_path, content)
            target = preview_path(guard_path)
            target.write_text(content, encoding="utf-8")
            print(f"preview: {target.relative_to(REPO_ROOT)}")
            continue

        guard_path.write_text(content, encoding="utf-8")
        print(f"updated: {guard_path.relative_to(REPO_ROOT)}")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except GenerateError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
