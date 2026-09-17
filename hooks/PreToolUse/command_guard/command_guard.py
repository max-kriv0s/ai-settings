#!/usr/bin/env python3
"""PreToolUse guard: what the agent is about to RUN.

Scope: the command itself and the paths it names. Text the agent writes is checked by
write_guard, text a tool returned — by output_guard. Settings come from the yaml next to
this file; a missing section disables its rule rather than breaking the guard.
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
    "command_guard": {
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
        "destructive_commands": {
            "filesystem": [
                "^rm\\b",
                "^find\\b.*\\s-delete\\b",
                "^find\\b.*\\s-exec\\s+rm\\b",
                "^(shred|unlink)\\b",
                ">\\s*/dev/sd[a-z]",
            ],
            "git": [
                "^git\\s+(?:-{1,2}[\\w-]+(?:=\\S+)?(?:\\s+\\S+)?\\s+)*push\\b",
                "^git\\s+reset\\b.*--hard\\b",
                "^git\\s+branch\\s+-D\\b",
                "^git\\s+filter-(branch|repo)\\b",
                "^git\\s+clean\\s+-[a-z]*f",
                "^git\\s+commit\\b.*--no-verify\\b",
                "^git\\s+commit\\b.*--amend\\b",
            ],
            "secret_exfiltration": [
                "^curl\\b.*\\s-d\\b.*(?:password|secret|token|api_key)=",
                "^wget\\b.*--post-data=.*(?:password|secret|token)",
            ],
            "package_install": [
                "^(npm|yarn|pnpm)\\s+(?:install|i|add|global)\\b",
                "^pip3?\\s+install\\b",
                "^uv\\s+(?:add|pip\\s+install|tool\\s+install)\\b",
                "^uv\\s+run\\b.*--with\\b",
                "^pipx\\s+install\\b",
                "^(gem|cargo|go|brew)\\s+install\\b",
            ],
        },
        "blocked_commands": {
            "environment_dump": [
                "^(env|set|export)\\s*$",
                "^export\\s+-p\\b",
                "^printenv\\b",
            ],
            "docker_config": [
                "^docker\\s+compose\\s+config\\b",
                "^docker-compose\\s+config\\b",
            ],
            "remote_access": [
                "^(ssh|scp|sftp|ssh-add|ssh-agent|ssh-keygen|ssh-copy-id)\\b",
                "\\b(IdentityFile|IdentitiesOnly|SSH_AUTH_SOCK)\\b",
                "(ssh://|git@[^:\\s]+:)",
            ],
        },
        "interpreters": {
            "names": ["python", "node", "ruby", "perl", "bash", "sh", "zsh"],
            "shells": ["bash", "sh", "zsh"],
            "valued_flags": [
                "-W",
                "-X",
                "-I",
                "-o",
                "--require",
                "--loader",
                "--import",
            ],
            "safe_flags": ["--version", "-V", "--help", "-h"],
            "wrappers": [
                "uv run",
                "poetry run",
                "sudo",
                "env",
                "timeout",
                "nohup",
                "nice",
                "xargs",
                "command",
                "exec",
                "time",
                "do",
                "then",
                "else",
            ],
            "wrapper_valued_flags": [
                "-u",
                "-I",
                "-s",
                "-n",
                "-g",
                "--user",
                "--signal",
            ],
        },
    }
}
# END AI_SETTINGS GENERATED


SETTINGS: dict[str, Any] = GUARD_SETTINGS.get("command_guard", {})

KEY_FILE_PATTERN = re.compile(r"(?i)^(id_rsa|id_dsa|id_ecdsa|id_ed25519)$")

# Sections shaped as {category: [regex]}. The category name is what the agent sees in the
# reason, so a new category needs no code change — only the yaml.
PATTERN_SECTIONS = ("destructive_commands", "blocked_commands")

# Path arguments of non-Bash tools: Read, Edit, Write, Glob, Grep, NotebookEdit.
PATH_INPUT_FIELDS = ("file_path", "path", "notebook_path")

# Shell separators, command substitution and newlines included. Each segment is analysed
# on its own, so `cat x.py | python3` is seen as reading stdin, `echo $(python3 -c ...)`
# cannot hide the interpreter, and a second line is not a blind spot.
# Plain parentheses are NOT separators: they occur in commit messages far more often than
# in subshells, and a message in parentheses must not look like a command.
SEGMENT_SEPARATOR = re.compile(r"\|\||&&|[|;&\n\r]|\$\(|<\(|`")

# Flags handing code to an interpreter. Short ones are matched inside a cluster, so `-Bc`
# counts as `-c`.
CODE_SHORT_FLAGS = ("c", "e")
CODE_LONG_FLAGS = ("--eval", "--command", "--exec")
MODULE_FLAG = "-m"
STDIN_ARG = "-"
HEREDOC_PREFIX = "<<"

# `python3.12` is the same interpreter as `python`; a leading `FOO=bar` is not a command.
INTERPRETER_VERSION_SUFFIX = re.compile(r"[\d.]+$")
ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

# A flag or a number right after a wrapper belongs to that wrapper, not to the command.
WRAPPER_ARGUMENT = re.compile(r"^(-|\d)")


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


def section(name: str) -> dict[str, Any]:
    return SETTINGS.get(name, {})


def command_tokens(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


def command_segments(command: str) -> list[str]:
    return [
        segment.strip()
        for segment in SEGMENT_SEPARATOR.split(command)
        if segment.strip()
    ]


def has_denied_path_segment(value: str, denied_segments: list[str]) -> bool:
    segments = [part for part in PurePath(value).parts if part not in {"", "/"}]
    return any(segment in denied_segments for segment in segments)


def matches_any(file_name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(file_name, pattern) for pattern in patterns)


def looks_like_path(value: str) -> bool:
    """A bare word is an argument, not a path: a word in `grep WORD README.md` is not one."""
    return "/" in value


def check_path(value: str, subject: str) -> str | None:
    """Return a reason why this path-like value is denied, or None when allowed."""
    paths = section("paths")

    if looks_like_path(value) and has_denied_path_segment(
        value, paths.get("deny_path_segments", [])
    ):
        return f"Blocked because {subject} references a denied path segment."

    file_name = PurePath(value).name
    if matches_any(file_name, paths.get("allow_environment_templates", [])):
        return None

    if matches_any(
        file_name, paths.get("deny_file_patterns", [])
    ) or KEY_FILE_PATTERN.match(file_name):
        return f"Blocked because {subject} may expose secrets or private key material."

    return None


def strip_command_prefix(
    tokens: list[str], wrappers: list[str], valued_flags: list[str]
) -> list[str]:
    """Drop leading `uv run`, `sudo`, `do`, `FOO=bar` so tokens[0] is the real command."""
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

            # Arguments of the wrapper itself: `timeout 5`, `xargs -0`, `nice -n 10`.
            # A flag that takes a value swallows it too, or `sudo -u deploy rm` would
            # leave `deploy` at position 0 and the real command would go unseen.
            while tokens and WRAPPER_ARGUMENT.match(tokens[0]):
                takes_value = tokens[0] in valued_flags
                tokens = tokens[1:]
                if takes_value and tokens:
                    tokens = tokens[1:]

            stripped = True
            break

    return tokens


def pattern_targets(command: str) -> list[str]:
    """Each segment as written, plus its form with wrappers stripped.

    Patterns are matched against segments, not the whole string, so `^` means "the command
    is": searching for a word inside quotes is not the same as running it. The original
    form is kept too — it carries flags belonging to the wrapper, as in `uv run --with x`.
    """
    interpreters = section("interpreters")
    wrappers = interpreters.get("wrappers", [])
    valued_flags = interpreters.get("wrapper_valued_flags", [])
    targets: list[str] = []

    for segment in command_segments(command):
        targets.append(segment)

        tokens = strip_command_prefix(command_tokens(segment), wrappers, valued_flags)
        if not tokens:
            continue

        # The base-name form only for an absolute path: `/bin/rm` is rm, while a relative
        # `./scripts/rm-cache.sh` is a project script that must not match `^rm`.
        forms = [tokens]
        if tokens[0].startswith("/"):
            forms.append([PurePath(tokens[0]).name, *tokens[1:]])

        for form in forms:
            normalized = " ".join(form)
            if normalized and normalized not in targets:
                targets.append(normalized)

    return targets


def inspect_patterns(command: str) -> str | None:
    """Match every segment against every pattern section; a broken regex is skipped."""
    for segment in pattern_targets(command):
        for name in PATTERN_SECTIONS:
            for category, patterns in section(name).items():
                for pattern in patterns:
                    try:
                        matched = re.search(pattern, segment, re.IGNORECASE)
                    except re.error:
                        continue

                    if matched is not None:
                        return f"Blocked because the command matches a blocked pattern ({category})."

    return None


def interpreter_name(token: str) -> str:
    """`/usr/bin/python3.12` and `python3` both answer to `python`."""
    return INTERPRETER_VERSION_SUFFIX.sub("", PurePath(token).name)


def is_code_flag(argument: str, short_flags: tuple[str, ...]) -> bool:
    """`-c`, `-e`, `-Bc`, `--eval` — anything that hands the interpreter code to run."""
    if argument in CODE_LONG_FLAGS:
        return True

    if argument.startswith("--"):
        return False

    return argument.startswith("-") and any(
        flag in argument[1:] for flag in short_flags
    )


def reads_code_from_argument_or_stdin(
    tokens: list[str],
    valued_flags: list[str],
    short_flags: tuple[str, ...],
    safe_flags: list[str],
    is_shell: bool,
) -> bool:
    """True when the interpreter takes code inline or from stdin instead of a file."""
    skip_next = False

    for argument in tokens[1:]:
        if skip_next:
            skip_next = False
            continue

        # `--version`, `--help`: prints and exits, no code involved.
        if argument in safe_flags:
            return False

        # For a shell `-m` is job control, not a module.
        if argument == MODULE_FLAG and not is_shell:
            return False

        if (
            argument == STDIN_ARG
            or argument.startswith(HEREDOC_PREFIX)
            or is_code_flag(argument, short_flags)
        ):
            return True

        if argument in valued_flags:
            skip_next = True
            continue

        if not argument.startswith("-"):
            return False

    return True


def inspect_interpreters(command: str) -> str | None:
    settings = section("interpreters")
    names = settings.get("names", [])
    shells = settings.get("shells", [])
    wrappers = settings.get("wrappers", [])
    wrapper_valued_flags = settings.get("wrapper_valued_flags", [])
    valued_flags = settings.get("valued_flags", [])
    safe_flags = settings.get("safe_flags", [])

    for segment in command_segments(command):
        tokens = strip_command_prefix(
            command_tokens(segment), wrappers, wrapper_valued_flags
        )
        if not tokens:
            continue

        name = interpreter_name(tokens[0])
        if name not in names:
            continue

        # A shell takes code only via -c; its -e is errexit, not a script.
        is_shell = name in shells
        short_flags = ("c",) if is_shell else CODE_SHORT_FLAGS

        if reads_code_from_argument_or_stdin(
            tokens, valued_flags, short_flags, safe_flags, is_shell
        ):
            return "Blocked because the command runs inline code instead of a file."

    return None


def inspect_cwd(payload: dict[str, Any]) -> str | None:
    """Stop any call made from inside a denied directory, whatever the arguments are."""
    cwd = payload.get("cwd")
    if not isinstance(cwd, str) or not cwd:
        return None

    denied = section("paths").get("deny_path_segments", [])
    if has_denied_path_segment(cwd, denied):
        return "Blocked because the working directory is inside a denied path segment."

    return None


def inspect_input_paths(tool_input: dict[str, Any]) -> str | None:
    """Path arguments of non-Bash tools (Read, Edit, Write, Glob, Grep)."""
    for field in PATH_INPUT_FIELDS:
        value = tool_input.get(field)
        if not isinstance(value, str) or not value:
            continue

        reason = check_path(value, "the target path")
        if reason is not None:
            return reason

    return None


def inspect_command_paths(command: str) -> str | None:
    for token in command_tokens(command):
        reason = check_path(token, "the command")
        if reason is not None:
            return reason

    return None


def inspect(payload: dict[str, Any]) -> str | None:
    reason = inspect_cwd(payload)
    if reason is not None:
        return reason

    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return None

    reason = inspect_input_paths(tool_input)
    if reason is not None:
        return reason

    if payload.get("tool_name") in {"Write", "Edit", "MultiEdit", "ApplyPatch"}:
        return None

    command = tool_input.get("command")
    if not isinstance(command, str) or not command:
        return None
    if command.startswith("*** Begin Patch"):
        return None

    reason = inspect_patterns(command)
    if reason is not None:
        return reason

    reason = inspect_interpreters(command)
    if reason is not None:
        return reason

    return inspect_command_paths(command)


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
