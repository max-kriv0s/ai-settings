"""Проверка цепочки guard-ов, а не каждого по отдельности.

Отдельный тест говорит «этот guard запретил бы». Здесь проверяется то, что происходит
на самом деле: вызов идёт через ВСЕ включённые guard-ы события, в том же порядке, в
котором их регистрирует sync, и первый запрет останавливает вызов.

Состав берётся из тех же yaml, что читает sync, — списка guard-ов здесь нет, поэтому
он не может разойтись с реальностью. Кейс проверяет и решение, и кто именно его принял:
запрет от не того guard-а означает, что правило лежит не там, где задумано.

Ничего не выполняется: payload уходит guard-у на stdin, ответ сверяется.
"""

from __future__ import annotations

import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, NamedTuple

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

from runner import (  # noqa: E402
    ALLOW,
    DENY,
    HookPayload,
    decide,
    proposed_bash,
    proposed_bash_in,
    proposed_read,
    proposed_write,
    tool_output,
)

ROOT = Path(__file__).resolve().parents[1]
HOOKS_DIR = ROOT / "hooks"

PRE_TOOL_USE = "PreToolUse"
POST_TOOL_USE = "PostToolUse"


class ChainCase(NamedTuple):
    expected: str  # DENY или ALLOW
    guard: str | None  # кто должен ответить; None для ALLOW
    name: str
    payload: HookPayload


def registered_guards(event: str) -> list[tuple[str, Path]]:
    """Включённые guard-ы события, в порядке обхода yaml — том же, что у sync."""
    guards: list[tuple[str, Path]] = []

    for config_path in sorted(HOOKS_DIR.rglob("*.yaml")):
        config: dict[str, Any] = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        for name, section in (config or {}).items():
            if name == "meta" or not isinstance(section, dict):
                continue

            if not section.get("enabled") or section.get("event") != event:
                continue

            guard = section.get("guard")
            if isinstance(guard, str):
                guards.append((name, ROOT / guard))

    return guards


def through_chain(event: str, payload: HookPayload) -> tuple[str, str | None]:
    """Первый guard, который не сказал allow, останавливает цепочку."""
    for name, guard in registered_guards(event):
        answer = decide(guard, payload)
        if answer != ALLOW:
            return answer, name

    return ALLOW, None


def build_cases(root: str) -> list[ChainCase]:
    path = Path(root)
    (path / "safe.py").write_text("print('ok')\n")
    (path / "reader.py").write_text('import shutil\nSOURCE = "config/.env"\n')

    return [
        # Опасная команда: до чтения файлов дело не доходит
        ChainCase(DENY, "command_guard", "удаление файлов", proposed_bash("rm -rf /tmp/x")),
        ChainCase(DENY, "command_guard", "отправка в origin", proposed_bash("git push")),
        ChainCase(
            DENY, "command_guard", "код аргументом", proposed_bash('python3 -c "print(1)"')
        ),
        ChainCase(
            DENY,
            "command_guard",
            "путь к ключам в команде",
            proposed_bash("cat fixtures/.ssh/config"),
        ),
        # Команда безобидна, опасен запускаемый файл — это уже следующий guard
        ChainCase(
            DENY,
            "script_guard",
            "скрипт обращается к запрещённому пути",
            proposed_bash_in(root, "python3 reader.py"),
        ),
        ChainCase(
            DENY,
            "script_guard",
            "обёртка не прячет скрипт",
            proposed_bash_in(root, "uv run python3 reader.py"),
        ),
        # Запись
        # Кейс на write_guard вписывает человек: он сам является записью секрета,
        # поэтому агент вставить его не может. Строка целиком:
        #     ChainCase(DENY, "write_guard", "секрет литералом в коде",
        #               proposed_write("fixtures/settings.py", "api_key = <секрет в кавычках>")),
        ChainCase(
            DENY,
            "command_guard",
            "запись по запрещённому пути",
            proposed_write("fixtures/.env", "TOKEN_NAME=x\n"),
        ),
        # Вывод инструмента
        ChainCase(
            DENY,
            "output_guard",
            "секрет в выводе",
            tool_output("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI0123456789"),
        ),
        # Обычная работа проходит всю цепочку
        ChainCase(ALLOW, None, "статус репозитория", proposed_bash("git status")),
        ChainCase(ALLOW, None, "запуск безопасного файла", proposed_bash_in(root, "python3 safe.py")),
        ChainCase(ALLOW, None, "чтение исходника", proposed_read("scripts/sync.py")),
        ChainCase(ALLOW, None, "обычный вывод", tool_output("README.md\npyproject.toml\n")),
    ]


def event_of(payload: HookPayload) -> str:
    return str(payload.get("hook_event_name", PRE_TOOL_USE))


def main(argv: list[str]) -> int:
    if argv:
        raise SystemExit("цепочка проверяется только на боевых guard-ах, без preview")

    with TemporaryDirectory() as root:
        cases = build_cases(root)

        for event in (PRE_TOOL_USE, POST_TOOL_USE):
            names = ", ".join(name for name, _ in registered_guards(event))
            print(f"{event}: {names}")

        print()
        failed = 0
        for expected, guard, name, payload in cases:
            answer, decided_by = through_chain(event_of(payload), payload)

            if answer == expected and (expected == ALLOW or decided_by == guard):
                where = f" ({decided_by})" if decided_by else ""
                print(f"  ok      {name:<36} {answer}{where}")
                continue

            failed += 1
            print(
                f"  FAIL    {name:<36} ожидали {expected}"
                f"{f' от {guard}' if guard else ''}, "
                f"получили {answer}{f' от {decided_by}' if decided_by else ''}"
            )

        print(f"\nитого: {len(cases) - failed} ok, {failed} fail")
        return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
