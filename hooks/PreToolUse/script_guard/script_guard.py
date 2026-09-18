#!/usr/bin/env python3
"""PreToolUse guard: what the file about to run DOES.

command_guard sees only the command line, and a command line says nothing about the
script behind it: `bash deploy.sh` and `task build` look the same whatever is inside.
This guard opens that file and refuses to run it when it names a denied path.

It is a filter, not a barrier: a path assembled at runtime cannot be seen here.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import shlex
import sys
from pathlib import Path, PurePath
from typing import Any

# BEGIN AI_SETTINGS GENERATED
GUARD_SETTINGS: dict[str, Any] = {'script_guard': {'paths': {'deny_path_segments': ['.ssh', 'ssh'],
                            'deny_file_patterns': ['.env',
                                                   '.env.*',
                                                   '*.local',
                                                   '*.local.*',
                                                   '*.secret',
                                                   '*.secrets',
                                                   '*.pem',
                                                   'credentials',
                                                   'credentials.json',
                                                   'credentials.yaml',
                                                   'credentials.yml',
                                                   '.netrc',
                                                   '.pgpass'],
                            'allow_environment_templates': ['*.example']},
                  'syntax': {'segment_separator': '\\|\\||&&|[|;&\\n\\r]|\\$\\(|<\\(|`'},
                  'interpreters': {'names': ['python', 'node', 'ruby', 'perl', 'bash', 'sh', 'zsh'],
                                   'shells': ['bash', 'sh', 'zsh'],
                                   'launchers': ['source', '.'],
                                   'wrappers': ['uv run',
                                                'poetry run',
                                                'sudo',
                                                'env',
                                                'timeout',
                                                'nohup',
                                                'nice',
                                                'xargs',
                                                'command',
                                                'exec',
                                                'time',
                                                'do',
                                                'then',
                                                'else'],
                                   'wrapper_valued_flags': ['-u',
                                                            '-I',
                                                            '-s',
                                                            '-n',
                                                            '-g',
                                                            '--user',
                                                            '--signal']},
                  'commands': {'read_commands': ['cat', 'sed', 'grep', 'rg', 'head', 'tail']},
                  'execution': {'max_bytes': 262144}}}
# END AI_SETTINGS GENERATED

SETTINGS: dict[str, Any] = GUARD_SETTINGS.get("script_guard", {})

# Only a path-like token is checked: a bare word such as `credentials` in a comment is
# prose, while `config/.env` and `.env` name a file. Same rule as command_guard uses.
PATH_TOKEN = re.compile(r"[~./A-Za-z0-9_-]+")

# A path built at runtime cannot be checked as text.
DYNAMIC_MARKS = ("$", "`", "*", "?", "[")

# `python3.12` and `python3` are the same launcher as `python`, as in command_guard.
VERSION_SUFFIX = re.compile(r"[\d.]+$")

# A leading `FOO=bar` is not a command; a flag or a number after a wrapper is its own.
ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
WRAPPER_ARGUMENT = re.compile(r"^(-|\d)")


def strip_command_prefix(tokens: list[str]) -> list[str]:
    """Drop leading `uv run`, `sudo`, `do`, `FOO=bar` so tokens[0] is the real command.

    The same step command_guard does, on the same lists from shared/interpreters.yaml.
    Without it `uv run python x.py` looks like `uv` and the script is never opened.
    """
    interpreters = section("interpreters")
    wrappers = interpreters.get("wrappers", [])
    valued_flags = interpreters.get("wrapper_valued_flags", [])

    stripped = True
    while stripped and tokens:
        stripped = False

        if ENV_ASSIGNMENT.match(tokens[0]):
            tokens = tokens[1:]
            stripped = True
            continue

        for wrapper in wrappers:
            parts = wrapper.split()
            # Compared by base name, so `/usr/bin/sudo` is stripped just like `sudo`.
            if [PurePath(token).name for token in tokens[: len(parts)]] != parts:
                continue

            tokens = tokens[len(parts) :]
            while tokens and WRAPPER_ARGUMENT.match(tokens[0]):
                takes_value = tokens[0] in valued_flags
                tokens = tokens[1:]
                if takes_value and tokens:
                    tokens = tokens[1:]

            stripped = True
            break

    return tokens


def deny(reason: str) -> None:
    """Both tools read this shape: Claude Code and Codex parse permissionDecision."""
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


def section(name: str) -> dict[str, Any]:
    value = SETTINGS.get(name, {})
    return value if isinstance(value, dict) else {}


def launcher_names() -> set[str]:
    """What runs a file: an interpreter, a shell, or `source`."""
    interpreters = section("interpreters")
    names = interpreters.get("names", [])
    return set(names) | set(interpreters.get("launchers", []))


def looks_like_path(value: str) -> bool:
    return "/" in value or value.startswith(".")


def denied(value: str) -> bool:
    """Каждая часть пути по обоим спискам: запрещённый каталог бывает и в середине."""
    paths = section("paths")
    segments = paths.get("deny_path_segments", [])
    denied_files = paths.get("deny_file_patterns", [])
    allowed = paths.get("allow_environment_templates", [])

    for chunk in value.split("="):
        for part in PurePath(chunk).parts:
            if part in {"", "/"}:
                continue

            if part in segments:
                return True

            if any(fnmatch.fnmatchcase(part, pattern) for pattern in allowed):
                continue

            if any(fnmatch.fnmatchcase(part, pattern) for pattern in denied_files):
                return True

    return False


def script_token(tokens: list[str]) -> tuple[str | None, str | None]:
    """Which token names the code being run — not every token that happens to exist.

    `/bin/ls docs` runs ls and reads nothing: the file at position 0 is a binary, and
    `docs` is an argument. Only a launcher's first argument, or a command given as a
    path, is a script.
    """
    launcher = VERSION_SUFFIX.sub("", PurePath(tokens[0]).name)
    if launcher in section("commands").get("read_commands", []):
        return None, None

    if launcher in launcher_names():
        rest = tokens[1:]
    elif looks_like_path(tokens[0]):
        rest = tokens[:1]
    else:
        return None, None

    for token in rest:
        if token.startswith("-") or token == "|":
            continue

        if any(mark in token for mark in DYNAMIC_MARKS):
            if looks_like_path(token) or "." in token:
                return None, "the script path is built at runtime"
            continue

        return token, None

    return None, None


def command_segments(command: str) -> list[str]:
    """`cd x && python3 y.py` is two commands; the second one is the script."""
    pattern = section("syntax").get("segment_separator", r"[|;&\n\r]")
    return [
        segment.strip() for segment in re.split(pattern, command) if segment.strip()
    ]


def changed_directory(tokens: list[str], current: Path) -> Path | None:
    """`cd sub && python x.py` runs x.py in sub, so the path must follow the cd.

    Resolved as text, the same way command_guard does it: `~` expanded, `..` collapsed.
    """
    if PurePath(tokens[0]).name != "cd":
        return None

    if len(tokens) < 2:
        return Path(os.path.expanduser("~"))

    target = tokens[1]
    if any(mark in target for mark in DYNAMIC_MARKS):
        return None

    expanded = os.path.expanduser(target)
    if not os.path.isabs(expanded):
        expanded = os.path.join(str(current), expanded)

    return Path(os.path.normpath(expanded))


def script_paths(command: str, cwd: str) -> tuple[list[Path], str | None]:
    paths: list[Path] = []
    current = Path(cwd)

    for segment in command_segments(command):
        # A `|` inside quotes splits the segment and leaves the quoting unbalanced, as in
        # `grep -E 'a|b'`. That is not a reason to refuse: fall back to a rough split the
        # way command_guard does, and let the launcher check decide.
        try:
            tokens = shlex.split(segment)
        except ValueError:
            tokens = segment.split()

        tokens = strip_command_prefix(tokens)
        if not tokens:
            continue

        moved = changed_directory(tokens, current)
        if moved is not None:
            current = moved
            continue

        token, reason = script_token(tokens)
        if reason is not None:
            return [], reason

        if token is None:
            continue

        candidate = Path(token) if Path(token).is_absolute() else current / token
        if candidate.is_file():
            paths.append(candidate)

    return paths, None


def script_text(path: Path) -> tuple[str | None, str | None]:
    """The first max_bytes of the file, or None when it is not readable text.

    A binary is not a script we can read, and its size is not a reason to refuse: a
    large generated script is checked by its beginning rather than blocked outright.
    """
    max_bytes = section("execution").get("max_bytes", 262144)
    if not isinstance(max_bytes, int):
        return None, "the guard has no size limit configured"

    try:
        with path.open("rb") as handle:
            chunk = handle.read(max_bytes)
    except OSError:
        return None, "the script cannot be read"

    try:
        return chunk.decode("utf-8"), None
    except UnicodeDecodeError:
        return None, None


def find_denied_line(content: str) -> bool:
    """Every line is checked. A script hides a read in whatever call it likes."""
    for line in content.splitlines():
        for value in PATH_TOKEN.findall(line):
            if looks_like_path(value) and denied(value):
                return True

    return False


def inspect(payload: dict[str, Any]) -> str | None:
    if payload.get("tool_name") in {"Write", "Edit", "MultiEdit", "ApplyPatch"}:
        return None

    tool_input = payload.get("tool_input")
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if not isinstance(command, str) or command.startswith("*** Begin Patch"):
        return None

    # Codex не присылает cwd вовсе — его payload это поле не содержит. Запрет здесь
    # остановил бы там каждую команду, поэтому берём каталог самого процесса: хук
    # запускается инструментом в каталоге сессии. Не разрешился путь — нечего и проверять.
    cwd = payload.get("cwd")
    if not isinstance(cwd, str) or not cwd:
        cwd = str(Path.cwd())

    paths, reason = script_paths(command, cwd)
    if reason is not None:
        return f"Blocked because {reason}."

    for path in paths:
        if denied(str(path)):
            return "Blocked because the script path itself is denied."

        content, reason = script_text(path)
        if reason is not None:
            return f"Blocked because {reason}."

        if content is not None and find_denied_line(content):
            return "Blocked because the script names a denied path."

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
