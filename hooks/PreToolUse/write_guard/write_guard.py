#!/usr/bin/env python3
"""PreToolUse guard: what the agent is about to WRITE.

Checked before the write happens: PostToolUse cannot take a file back off the disk.
Scope is the text only — the target path is checked by command_guard.
"""

from __future__ import annotations

import json
import re
import sys
from typing import Any

# BEGIN AI_SETTINGS GENERATED
GUARD_SETTINGS: dict[str, Any] = {
    "write_guard": {
        "secret_indicators": [
            "secret",
            "token",
            "api_key",
            "private_key",
            "password",
            "credential",
        ]
    }
}
# END AI_SETTINGS GENERATED


SETTINGS: dict[str, Any] = GUARD_SETTINGS.get("write_guard", {})

PRIVATE_KEY_PATTERN = re.compile(r"(?i)BEGIN (OPENSSH|RSA|DSA|EC) PRIVATE KEY")

# Text an agent hands to a write tool.
CONTENT_INPUT_FIELDS = ("content", "new_string", "new_source")

# A secret written into code by hand is a quoted literal; reading one from the environment
# is the correct thing to do and must pass. Hence the mandatory quote.
SECRET_ASSIGNMENT = r"(?i){indicator}\s*[:=]\s*['\"][^'\"\s]{{8,}}"


def deny(reason: str) -> None:
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            }
        )
    )
    sys.exit(0)


def written_content(tool_input: dict[str, Any]) -> list[str]:
    """Write.content, Edit.new_string, NotebookEdit.new_source, MultiEdit.edits[]."""
    chunks = [
        value
        for field in CONTENT_INPUT_FIELDS
        if isinstance(value := tool_input.get(field), str) and value
    ]

    edits = tool_input.get("edits")
    if isinstance(edits, list):
        for edit in edits:
            if isinstance(edit, dict) and isinstance(edit.get("new_string"), str):
                chunks.append(edit["new_string"])

    return chunks


def find_secret(text: str) -> str | None:
    if PRIVATE_KEY_PATTERN.search(text):
        return "Blocked because the text being written contains a private key block."

    for indicator in SETTINGS.get("secret_indicators", []):
        pattern = SECRET_ASSIGNMENT.format(indicator=re.escape(indicator))
        if re.search(pattern, text):
            # The value itself is never repeated back — only the name that matched.
            return (
                f"Blocked because the text being written assigns a literal to "
                f"'{indicator}' ({indicator}: ***)."
            )

    return None


def inspect(payload: dict[str, Any]) -> str | None:
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return None

    for chunk in written_content(tool_input):
        reason = find_secret(chunk)
        if reason is not None:
            return reason

    return None


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0

    if not isinstance(payload, dict):
        return 0

    if payload.get("hook_event_name") != "PreToolUse":
        return 0

    reason = inspect(payload)
    if reason is not None:
        deny(reason)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
