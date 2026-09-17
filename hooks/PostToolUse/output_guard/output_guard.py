#!/usr/bin/env python3
"""PostToolUse guard: what a tool RETURNED.

Runs after the call, so it cannot undo anything — it reports that the output carries
secret material. In Codex `decision: block` replaces the result; in Claude Code the
output still reaches the model, so there this guard is a signal, not a barrier.
"""

from __future__ import annotations

import fnmatch
import json
import re
import shlex
import sys
from pathlib import PurePath
from typing import Any

# BEGIN AI_SETTINGS GENERATED
GUARD_SETTINGS: dict[str, Any] = {
    "output_guard": {
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
        "secret_indicators": [
            "secret",
            "token",
            "api_key",
            "private_key",
            "password",
            "credential",
        ],
    }
}
# END AI_SETTINGS GENERATED


SETTINGS: dict[str, Any] = GUARD_SETTINGS.get("output_guard", {})

KEY_FILE_PATTERN = re.compile(r"(?i)^(id_rsa|id_dsa|id_ecdsa|id_ed25519)$")
PRIVATE_KEY_PATTERN = re.compile(r"(?i)BEGIN (OPENSSH|RSA|DSA|EC) PRIVATE KEY")

# In output a leaked value has no quotes around it: `AWS_SECRET_ACCESS_KEY=wJalr...`.
# An indicator must be a complete name component: `token_value` is suspicious, while
# a normal implementation variable such as `tokens` is not.
SECRET_ASSIGNMENT = (
    r"(?i)(?<![A-Za-z0-9])(?:[A-Za-z0-9]+[_.-])*{indicator}"
    r"(?:[_.-][A-Za-z0-9]+)*\s*[:=]\s*['\"]?[^'\"\s]{{8,}}"
)

TOKEN_PATTERN = re.compile(r"[\w./~:-]+")


def block(reason: str) -> None:
    print(
        json.dumps(
            {
                "decision": "block",
                "reason": reason,
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "additionalContext": reason,
                },
            }
        )
    )
    sys.exit(0)


def response_text(tool_response: Any) -> str:
    """Flatten to text; escaped newlines would glue `\\n` onto the next token."""
    text = (
        tool_response
        if isinstance(tool_response, str)
        else json.dumps(tool_response, ensure_ascii=False)
    )
    return text.replace("\\n", " ").replace("\\t", " ")


def is_plain_text_read(payload: dict[str, Any]) -> bool:
    """Whether this result came from a single non-executing text reader command."""
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return False

    command = tool_input.get("command")
    if not isinstance(command, str):
        return False

    if re.search(r"[|;&`<>]|\$\(|<\(", command):
        return False

    try:
        tokens = shlex.split(command)
    except ValueError:
        return False

    if not tokens:
        return False

    return PurePath(tokens[0]).name in {"cat", "sed", "grep", "rg", "head", "tail"}


def matches_any(file_name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(file_name, pattern) for pattern in patterns)


def find_denied_path(text: str) -> str | None:
    """A path in the output means the file was reached, whatever the call looked like."""
    paths = SETTINGS.get("paths", {})
    denied_segments = paths.get("deny_path_segments", [])
    denied_files = paths.get("deny_file_patterns", [])
    allowed = paths.get("allow_environment_templates", [])

    for token in TOKEN_PATTERN.findall(text):
        file_name = PurePath(token).name
        if matches_any(file_name, allowed):
            continue

        if "/" in token:
            segments = [part for part in PurePath(token).parts if part not in {"", "/"}]
            if any(segment in denied_segments for segment in segments):
                return (
                    "Blocked because the tool output references a denied path segment."
                )

        if matches_any(file_name, denied_files) or KEY_FILE_PATTERN.match(file_name):
            return "Blocked because the tool output names a file that may hold secrets."

    return None


def find_secret(text: str) -> str | None:
    if PRIVATE_KEY_PATTERN.search(text):
        return "Blocked because the tool output contains a private key block."

    for indicator in SETTINGS.get("secret_indicators", []):
        pattern = SECRET_ASSIGNMENT.format(indicator=re.escape(indicator))
        if re.search(pattern, text):
            # The value itself is never repeated back — only the name that matched.
            return (
                f"Blocked because the tool output assigns a value to "
                f"'{indicator}' ({indicator}: ***)."
            )

    return None


def inspect(payload: dict[str, Any]) -> str | None:
    text = response_text(payload.get("tool_response"))

    if not is_plain_text_read(payload):
        reason = find_denied_path(text)
        if reason is not None:
            return reason

    return find_secret(text)


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0

    if not isinstance(payload, dict):
        return 0

    if payload.get("hook_event_name") != "PostToolUse":
        return 0

    reason = inspect(payload)
    if reason is not None:
        block(reason)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
