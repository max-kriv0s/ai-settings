"""Проверка синка permissions в config.toml Codex.

Формат вывода тот же, что у guard-тестов: строка на проверку и итог. Голый `assert`
здесь не годится — он молчит при успехе, и пустой вывод не отличить от пустого теста.

Ничего не применяется: документ разбирается и собирается в памяти, файл создаётся
только временный.
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from codex import backup_config_once, merge_permissions_document  # noqa: E402
from contracts import Permission  # noqa: E402

DOCUMENT = """approval_policy = "on-request"
default_permissions = "global-workspace"
model = "test-model"

[permissions.global-workspace]
extends = ":workspace"

[permissions.global-workspace.network]
enabled = true

[permissions.global-workspace.filesystem]
glob_scan_max_depth = 10
"~/.ssh" = "deny"

[permissions.global-workspace.filesystem.":workspace_roots"]
"**/.env*" = "deny"
"**/*.example" = "read"
"**/*.local" = "deny"
"""


class Check(NamedTuple):
    name: str
    actual: Any
    expected: Any


def read_policy() -> Permission:
    return Permission(
        name="read_policy",
        config={
            "deny_path_segments": [".ssh", "ssh"],
            "deny_file_patterns": [
                ".env",
                ".env.*",
                "*.local",
                "*.local.*",
                "*.secret",
            ],
            "allow_environment_templates": ["*.example"],
        },
    )


def merge_checks() -> list[Check]:
    settings = tomllib.loads(merge_permissions_document(DOCUMENT, [read_policy()]))
    profile = settings["permissions"]["global-workspace"]
    filesystem = profile["filesystem"]
    workspace = filesystem[":workspace_roots"]

    return [
        # Чужие настройки переживают запись
        Check("политика подтверждений", settings["approval_policy"], "on-request"),
        Check("модель", settings["model"], "test-model"),
        Check("сеть профиля", profile["network"]["enabled"], True),
        Check("глубина обхода", filesystem["glob_scan_max_depth"], 10),
        Check("запрет каталога ключей", filesystem["~/.ssh"], "deny"),
        # Наши правила попадают в профиль
        Check("запрет .local", workspace["**/*.local"], "deny"),
        Check("запрет .local.*", workspace["**/*.local.*"], "deny"),
        Check("запрет .secret", workspace["**/*.secret"], "deny"),
        # `.env.example` подходит и под запрет, и под разрешение сразу. Приоритета по
        # специфичности у Codex нет — на таком профиле он падает при загрузке конфига,
        # поэтому шаблоны окружения в него не пишутся вовсе.
        Check("шаблон не разрешается поверх запрета", "**/*.example" in workspace, False),
        Check("прежний шаблон .env заменён нашими", "**/.env*" in workspace, False),
    ]


def backup_check() -> Check:
    """Копия делается один раз за запуск: второй вызов не затирает исходный файл."""
    with TemporaryDirectory() as root:
        config = Path(root) / "config.toml"
        backup = Path(root) / "config.toml.bak"

        config.write_text("first", encoding="utf-8")
        backup_config_once(config)
        config.write_text("second", encoding="utf-8")
        backup_config_once(config)

        return Check("копия один раз за запуск", backup.read_text(encoding="utf-8"), "first")


def main() -> int:
    print("codex permissions\n")

    checks = [*merge_checks(), backup_check()]

    failed = 0
    for name, actual, expected in checks:
        if actual == expected:
            print(f"  ok      {name:<36} {actual}")
            continue

        failed += 1
        print(f"  FAIL    {name:<36} ожидали {expected}, получили {actual}")

    print(f"\nитого: {len(checks) - failed} ok, {failed} fail")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
