from __future__ import annotations

import fnmatch
import json
import re
import shlex
import sys
from pathlib import Path, PurePath
from typing import Any

# BEGIN AI_SETTINGS GENERATED
GUARD_SETTINGS: dict[str, Any] = {
    "script_guard": {
        "paths": {
            "deny_path_segments": [".ssh", "ssh"],
            "deny_file_patterns": [
                ".env",
                ".env.*",
                "*.local.*",
                "*.secret",
                "*.secrets",
                "*.pem",
                "credentials",
                "credentials.json",
                "credentials.yaml",
                "credentials.yml",
                ".netrc",
                ".pgpass",
            ],
            "allow_environment_templates": ["*.example"],
        },
        "execution": {"max_bytes": 262144},
    }
}
# END AI_SETTINGS GENERATED

SETTINGS = GUARD_SETTINGS.get("script_guard", {})
SHELL_SYNTAX = re.compile(r"[|;&`<>]|\$\(|<\(")
RISKY_OPERATION = re.compile(
    r"\b(cat|sed|grep|awk|open|read_text|read_bytes|subprocess|Popen|run|system|exec)\b"
)


def deny(reason: str) -> None:
    print(
        json.dumps(
            {
                "decision": "block",
                "reason": reason,
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "additionalContext": reason,
                },
            }
        )
    )
    sys.exit(0)


def policy() -> dict[str, Any]:
    value = SETTINGS.get("paths", {})
    return value if isinstance(value, dict) else {}


def denied(value: str) -> bool:
    paths = policy()
    parts = [part for part in PurePath(value).parts if part not in {"", "/"}]
    if any(part in paths.get("deny_path_segments", []) for part in parts):
        return True
    name = PurePath(value).name
    if any(
        fnmatch.fnmatchcase(name, pattern)
        for pattern in paths.get("allow_environment_templates", [])
    ):
        return False
    return any(
        fnmatch.fnmatchcase(name, pattern)
        for pattern in paths.get("deny_file_patterns", [])
    )


def targets(command: str, cwd: str) -> tuple[list[Path], str | None]:
    try:
        tokens = shlex.split(command.replace("|", " | "))
    except ValueError:
        return [], "ambiguous shell syntax"

    result: list[Path] = []
    if not tokens:
        return result, None

    launcher = Path(tokens[0]).name
    if launcher in {"bash", "sh", "zsh", "source", "."}:
        values = tokens[1:]
    elif tokens[0].startswith(("./", "/")):
        values = tokens[:1]
    else:
        return result, None

    for token in values:
        if token in {"|", "-"} or token.startswith("-"):
            continue
        if any(mark in token for mark in ("$", "`", "*", "?", "[")):
            if "/" in token or "." in token:
                return [], "dynamic file path"
            continue
        candidate = Path(token) if Path(token).is_absolute() else Path(cwd) / token
        if candidate.is_file():
            result.append(candidate)
    return result, None


def inspect(payload: dict[str, Any]) -> str | None:
    if payload.get("tool_name") in {"Write", "Edit", "MultiEdit", "ApplyPatch"}:
        return None

    tool_input = payload.get("tool_input")
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if not isinstance(command, str):
        return None
    if command.startswith("*** Begin Patch"):
        return None
    cwd = payload.get("cwd")
    if not isinstance(cwd, str):
        return "Blocked because script cwd is missing."
    files, reason = targets(command, cwd)
    if reason:
        return f"Blocked because {reason}."
    for candidate in files:
        if denied(str(candidate)):
            return "Blocked because the script path is denied."
        try:
            path = candidate.resolve(strict=True)
            max_bytes = SETTINGS.get("execution", {}).get("max_bytes", 262144)
            if (
                not path.is_file()
                or not isinstance(max_bytes, int)
                or path.stat().st_size > max_bytes
            ):
                return "Blocked because script cannot be inspected safely."
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return "Blocked because script cannot be inspected safely."
        if denied(str(path)):
            return "Blocked because the script path is denied."
        for line in content.splitlines():
            if RISKY_OPERATION.search(line):
                for value in re.findall(r"[~./A-Za-z0-9_-]+", line):
                    if denied(value):
                        return "Blocked because script operates on a denied path."
    return None


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0
    if isinstance(payload, dict) and payload.get("hook_event_name") == "PreToolUse":
        reason = inspect(payload)
        if reason:
            deny(reason)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
