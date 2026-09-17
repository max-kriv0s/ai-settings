from __future__ import annotations

import sys
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from runner import ALLOW, DENY, Case, proposed_bash_in, run

GUARD = Path(__file__).resolve().parent / "script_guard.py"


def main(argv: list[str]) -> int:
    with TemporaryDirectory() as root:
        path = Path(root)
        (path / "safe.py").write_text("print('ok')\n")
        (path / "unsafe.sh").write_text("cat " + "." + "en" + "v\n")
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
                ALLOW,
                "код из stdin оставлен command_guard",
                proposed_bash_in(root, "ba" + "sh -"),
            ),
        ]
        return run(GUARD, cases, argv)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
