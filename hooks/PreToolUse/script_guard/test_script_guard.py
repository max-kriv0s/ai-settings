from __future__ import annotations

import sys
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from runner import ALLOW, DENY, Case, proposed_bash, proposed_bash_in, run

GUARD = Path(__file__).resolve().parent / "script_guard.py"


def main(argv: list[str]) -> int:
    with TemporaryDirectory() as root:
        path = Path(root)
        (path / "safe.py").write_text("print('ok')\n")
        (path / "unsafe.sh").write_text("cat " + "." + "en" + "v\n")
        (path / "unsafe.py").write_text("open(" + "'.env'" + ").read()\n")
        # Ни одного слова из прежнего списка рискованных операций: до правки проходило.
        (path / "copy.py").write_text('import shutil\nSOURCE = "config/.env"\n')
        # Слово-индикатор без пути — это проза, а не обращение к файлу.
        (path / "prose.py").write_text('"""Работа с credentials пользователя."""\n')
        (path / "guide.md").write_text("Example: cat " + "." + "en" + "v\n")
        cases = [
            Case(
                ALLOW,
                "документ не считается скриптом",
                proposed_bash_in(root, "sed -n '1p' guide.md"),
            ),
            Case(
                ALLOW, "безопасный файл", proposed_bash_in(root, "py" + "thon safe.py")
            ),
            Case(
                DENY,
                "скрипт читает запрещённое",
                proposed_bash_in(root, "ba" + "sh unsafe.sh"),
            ),
            Case(
                DENY,
                "файл-аргумент интерпретатора тоже скрипт",
                proposed_bash_in(root, "py" + "thon unsafe.py"),
            ),
            Case(
                DENY,
                "путь без известного вызова чтения",
                proposed_bash_in(root, "py" + "thon copy.py"),
            ),
            Case(
                ALLOW,
                "слово-индикатор в тексте, а не путь",
                proposed_bash_in(root, "py" + "thon prose.py"),
            ),
            Case(
                ALLOW,
                "бинарник не скрипт",
                proposed_bash_in(root, "/bin/ls safe.py"),
            ),
            Case(
                ALLOW,
                "аргумент команды не скрипт",
                proposed_bash_in(root, "wc -l unsafe.sh"),
            ),
            Case(
                DENY,
                "первая команда не скрывает вторую",
                proposed_bash_in(root, "cd . && py" + "thon copy.py"),
            ),
            Case(
                DENY,
                "переход в каталог учитывается",
                proposed_bash_in(
                    str(path.parent), f"cd {path.name} && py" + "thon copy.py"
                ),
            ),
            Case(
                DENY,
                "версия в имени интерпретатора не прячет скрипт",
                proposed_bash_in(root, "py" + "thon3.12 copy.py"),
            ),
            Case(
                DENY,
                "обёртка не прячет скрипт",
                proposed_bash_in(root, "uv run py" + "thon copy.py"),
            ),
            Case(
                DENY,
                "обёртка с флагом-значением",
                proposed_bash_in(root, "sudo -u deploy py" + "thon copy.py"),
            ),
            Case(
                ALLOW,
                "код из stdin оставлен command_guard",
                proposed_bash_in(root, "ba" + "sh -"),
            ),
            # Codex не присылает cwd: запрет здесь остановил бы там каждую команду.
            Case(ALLOW, "вызов без cwd", proposed_bash("git status")),
        ]
        return run(GUARD, cases, argv)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
