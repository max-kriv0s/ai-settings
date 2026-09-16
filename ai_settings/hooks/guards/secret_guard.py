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
    "pre_tool_use": {
        "read_guard": {
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
            "order": [
                "deny_path_segments",
                "allow_environment_templates",
                "deny_secret_file_patterns",
                "allow_project_source_and_config_files",
                "report_sensitive_content",
            ],
            "allow_extensions": [
                ".go",
                ".py",
                ".ts",
                ".js",
                ".json",
                ".yaml",
                ".yml",
                ".toml",
                ".md",
            ],
            "allow_file_names": ["Dockerfile", "Taskfile.yml", "go.mod", "go.sum"],
        },
        "destructive_guard": {
            "filesystem_destruction": [
                "^rm\\b",
                "^find\\b.*\\s-delete\\b",
                "^find\\b.*\\s-exec\\s+rm\\b",
                "^(shred|unlink)\\b",
                ">\\s*/dev/sd[a-z]",
            ],
            "git_destruction": [
                "^git\\s+(?:-C\\s+\\S+\\s+)?push\\b",
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
            "ssh_access": [
                "^(ssh|scp|sftp|ssh-add|ssh-agent|ssh-keygen|ssh-copy-id)\\b",
                "\\b(IdentityFile|IdentitiesOnly|SSH_AUTH_SOCK)\\b",
                "(ssh://|git@[^:\\s]+:)",
            ],
        },
        "write_guard": {
            "allow_mention_extensions": [".md", ".yaml", ".yml"],
            "deny_content_patterns": ["\\bssh\\b", "\\bscp\\b", "\\bsftp\\b"],
        },
        "interpreter_guard": {
            "interpreters": ["python", "node", "ruby", "perl", "bash", "sh", "zsh"],
            "wrappers": ["uv run", "poetry run", "sudo", "env"],
        },
    },
    "post_tool_use": {
        "sensitive_output_guard": {
            "indicators": [
                "secret",
                "token",
                "api_key",
                "private_key",
                "password",
                "credential",
            ],
            "behavior": "Блокировать или редактировать значения; "
            "агент сообщает только путь и имя "
            "настройки.",
        }
    },
}
# END AI_SETTINGS GENERATED


KEY_FILE_PATTERN = re.compile(r"(?i)^(id_rsa|id_dsa|id_ecdsa|id_ed25519)$")
PRIVATE_KEY_PATTERN = re.compile(r"(?i)BEGIN (OPENSSH|RSA|DSA|EC) PRIVATE KEY")

# Sections of pre_tool_use shaped as {category: [regex]}. The category name is what the
# agent sees in the reason, so a new category needs no code change — only hooks.yaml.
PATTERN_SECTIONS = ("destructive_guard", "blocked_commands")

# Path arguments of non-Bash tools: Read, Edit, Write, Glob, Grep, NotebookEdit.
PATH_INPUT_FIELDS = ("file_path", "path", "notebook_path")

# Text an agent hands to a write tool, checked before it reaches the disk.
CONTENT_INPUT_FIELDS = ("content", "new_string", "new_source")

# Shell separators, command substitution included. Each segment is analysed on its own, so
# `cat x.py | python3` is seen as reading stdin, and `echo $(python3 -c ...)` cannot hide
# the interpreter behind another command.
# Plain parentheses are NOT separators: they occur in commit messages far more often than
# in subshells, and `git commit -m 'fix (ssh timeout)'` must not look like an ssh call.
SEGMENT_SEPARATOR = re.compile(r"\|\||&&|[|;&]|\$\(|<\(|`")

# Flags passing code as an argument, and the module flag, allowed explicitly: without it
# `python3 -m pytest` would look like an interpreter with no file, that is, reading stdin.
# Short flags are matched inside a cluster, so `-Bc` counts as `-c`.
CODE_SHORT_FLAGS = ("c", "e")
CODE_LONG_FLAGS = ("--eval", "--command", "--exec")
MODULE_FLAG = "-m"
STDIN_ARG = "-"
HEREDOC_PREFIX = "<<"

# `python3.12` is the same interpreter as `python`; a leading `FOO=bar` is not a command.
INTERPRETER_VERSION_SUFFIX = re.compile(r"[\d.]+$")
ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def deny_pre(reason: str) -> None:
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


def block_post(reason: str) -> None:
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


def guard_section(event: str, name: str) -> dict[str, Any]:
    """One accessor for every generated section; a missing section disables its rule."""
    return GUARD_SETTINGS.get(event, {}).get(name, {})


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
    """A bare word is an argument, not a path: `grep ssh README.md` must not be a match."""
    return "/" in value


def check_path(value: str, settings: dict[str, Any], subject: str) -> str | None:
    """Return a reason why this path-like value is denied, or None when allowed."""
    if looks_like_path(value) and has_denied_path_segment(
        value, settings.get("deny_path_segments", [])
    ):
        return f"Blocked because {subject} references a denied path segment."

    file_name = PurePath(value).name
    if matches_any(file_name, settings.get("allow_environment_templates", [])):
        return None

    if matches_any(
        file_name, settings.get("deny_file_patterns", [])
    ) or KEY_FILE_PATTERN.match(file_name):
        return f"Blocked because {subject} may expose secrets, local env files, or SSH private material."

    return None


def inspect_tokens(tokens: list[str], subject: str) -> str | None:
    """Check every token that may be a path — used for both commands and tool output."""
    settings = guard_section("pre_tool_use", "read_guard")

    for token in tokens:
        reason = check_path(token, settings, subject)
        if reason is not None:
            return reason

    return None


def pattern_targets(command: str) -> list[str]:
    """Each segment as written, plus its form with `sudo` / `uv run` / `FOO=bar` stripped.

    Patterns are matched against segments, not against the whole string, so `^` means
    "the command is" — `grep -rn 'git push' docs/` is a grep, not a push. Both forms are
    kept: the stripped one catches `sudo ssh host`, the original one keeps flags that
    belong to the wrapper itself, as in `uv run --with pkg`.
    """
    wrappers = guard_section("pre_tool_use", "interpreter_guard").get("wrappers", [])
    targets = []

    for segment in command_segments(command):
        targets.append(segment)

        tokens = strip_command_prefix(command_tokens(segment), wrappers)
        normalized = " ".join(tokens)
        if normalized and normalized != segment:
            targets.append(normalized)

    return targets


def inspect_patterns(command: str) -> str | None:
    """Match every segment against every pattern section; a broken regex is skipped."""
    for segment in pattern_targets(command):
        for section in PATTERN_SECTIONS:
            for category, patterns in guard_section("pre_tool_use", section).items():
                for pattern in patterns:
                    try:
                        matched = re.search(pattern, segment, re.IGNORECASE)
                    except re.error:
                        continue

                    if matched is not None:
                        return f"Blocked because the command matches a blocked pattern ({category})."

    return None


def strip_command_prefix(tokens: list[str], wrappers: list[str]) -> list[str]:
    """Drop leading `uv run`, `sudo` and `FOO=bar` so that tokens[0] is the real command."""
    stripped = True
    while stripped and tokens:
        stripped = False

        if ENV_ASSIGNMENT.match(tokens[0]):
            tokens = tokens[1:]
            stripped = True
            continue

        for wrapper in wrappers:
            parts = wrapper.split()
            if tokens[: len(parts)] == parts:
                tokens = tokens[len(parts) :]
                stripped = True
                break

    return tokens


def interpreter_name(token: str) -> str:
    """`/usr/bin/python3.12` and `python3` both answer to `python`."""
    return INTERPRETER_VERSION_SUFFIX.sub("", PurePath(token).name)


def is_code_flag(argument: str) -> bool:
    """`-c`, `-e`, `-Bc`, `--eval` — anything that hands the interpreter code to run."""
    if argument in CODE_LONG_FLAGS:
        return True

    if argument.startswith("--"):
        return False

    return argument.startswith("-") and any(
        flag in argument[1:] for flag in CODE_SHORT_FLAGS
    )


def reads_code_from_argument_or_stdin(tokens: list[str]) -> bool:
    """True when the interpreter takes code inline or from stdin instead of a file or module."""
    for argument in tokens[1:]:
        if argument == MODULE_FLAG:
            return False

        if (
            argument == STDIN_ARG
            or argument.startswith(HEREDOC_PREFIX)
            or is_code_flag(argument)
        ):
            return True

        if not argument.startswith("-"):
            return False

    return True


def inspect_interpreters(command: str) -> str | None:
    settings = guard_section("pre_tool_use", "interpreter_guard")
    interpreters = settings.get("interpreters", [])
    wrappers = settings.get("wrappers", [])

    for segment in command_segments(command):
        tokens = strip_command_prefix(command_tokens(segment), wrappers)
        if not tokens or interpreter_name(tokens[0]) not in interpreters:
            continue

        if reads_code_from_argument_or_stdin(tokens):
            return "Blocked because the command runs inline code instead of a file or a module."

    return None


def inspect_cwd(payload: dict[str, Any]) -> str | None:
    """Stop any call made from inside ~/.ssh and friends, whatever the tool arguments are."""
    cwd = payload.get("cwd")
    if not isinstance(cwd, str) or not cwd:
        return None

    denied_segments = guard_section("pre_tool_use", "read_guard").get(
        "deny_path_segments", []
    )
    if has_denied_path_segment(cwd, denied_segments):
        return "Blocked because the working directory is inside a denied path segment."

    return None


def inspect_input_paths(tool_input: dict[str, Any]) -> str | None:
    """Check path arguments of non-Bash tools (Read, Edit, Write, Glob, Grep)."""
    settings = guard_section("pre_tool_use", "read_guard")

    for field in PATH_INPUT_FIELDS:
        value = tool_input.get(field)
        if not isinstance(value, str) or not value:
            continue

        reason = check_path(value, settings, "the target path")
        if reason is not None:
            return reason

    return None


def response_text(tool_response: Any) -> str:
    """Flatten a tool response to text; escaped newlines would glue `\\n` onto the next token."""
    text = (
        tool_response
        if isinstance(tool_response, str)
        else json.dumps(tool_response, ensure_ascii=False)
    )
    return text.replace("\\n", " ").replace("\\t", " ")


def output_tokens(response: str) -> list[str]:
    return re.findall(r"[\w./~:-]+", response)


def inspect_secret_material(text: str, subject: str) -> str | None:
    """Look for secrets in text — used both for tool output and for text about to be written."""
    indicators = guard_section("post_tool_use", "sensitive_output_guard").get(
        "indicators", []
    )

    if PRIVATE_KEY_PATTERN.search(text):
        return f"Blocked because {subject} contains a private key block."

    for indicator in indicators:
        pattern = rf"(?i){re.escape(indicator)}\s*[:=]\s*['\"]?[^'\"\s]{{8,}}"
        if re.search(pattern, text):
            # The value itself is never repeated back — only the name that matched.
            return f"Blocked because {subject} assigns a value to '{indicator}' ({indicator}: ***)."

    return None


def written_content(tool_input: dict[str, Any]) -> list[str]:
    """Text an agent is about to write: Write.content, Edit.new_string, MultiEdit.edits[]."""
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


def mention_allowed(tool_input: dict[str, Any], settings: dict[str, Any]) -> bool:
    """Documentation and config can mention ssh: unlike a script, they cannot be run."""
    allowed = settings.get("allow_mention_extensions", [])

    for field in PATH_INPUT_FIELDS:
        value = tool_input.get(field)
        if isinstance(value, str) and value:
            return PurePath(value).suffix.lower() in allowed

    return False


def inspect_input_content(tool_input: dict[str, Any]) -> str | None:
    """Check the text before it reaches the disk — PostToolUse cannot take a file back."""
    settings = guard_section("pre_tool_use", "write_guard")
    allow_mention = mention_allowed(tool_input, settings)

    for chunk in written_content(tool_input):
        reason = inspect_secret_material(chunk, "the text being written")
        if reason is not None:
            return reason

        if allow_mention:
            continue

        for pattern in settings.get("deny_content_patterns", []):
            try:
                matched = re.search(pattern, chunk, re.IGNORECASE)
            except re.error:
                continue

            if matched is not None:
                return (
                    "Blocked because the text being written mentions remote access "
                    "outside documentation."
                )

    return None


def inspect_pre_tool_use(payload: dict[str, Any]) -> str | None:
    reason = inspect_cwd(payload)
    if reason is not None:
        return reason

    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return None

    reason = inspect_input_paths(tool_input)
    if reason is not None:
        return reason

    reason = inspect_input_content(tool_input)
    if reason is not None:
        return reason

    # A non-string command is not something this guard can parse; other rules already ran.
    command = tool_input.get("command")
    if not isinstance(command, str) or not command:
        return None

    reason = inspect_patterns(command)
    if reason is not None:
        return reason

    reason = inspect_interpreters(command)
    if reason is not None:
        return reason

    return inspect_tokens(command_tokens(command), "the command")


def inspect_post_tool_use(payload: dict[str, Any]) -> str | None:
    response = response_text(payload.get("tool_response"))

    reason = inspect_tokens(output_tokens(response), "the tool output")
    if reason is not None:
        return reason

    return inspect_secret_material(response, "the tool output")


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0

    if not isinstance(payload, dict):
        return 0

    event = payload.get("hook_event_name")

    if event == "PreToolUse":
        reason = inspect_pre_tool_use(payload)
        if reason is not None:
            deny_pre(reason)

        return 0

    if event == "PostToolUse":
        reason = inspect_post_tool_use(payload)
        if reason is not None:
            block_post(reason)

        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
