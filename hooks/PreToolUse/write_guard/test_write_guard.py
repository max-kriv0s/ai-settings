"""Smoke checks for write_guard. See hooks/runner.py — nothing here is written to disk.

Часть DENY-кейсов этого файла содержит ровно тот текст, который write_guard запрещает
записывать, поэтому агент их вставить не может — они добавляются человеком.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from runner import ALLOW, DENY, Case, proposed_edit, proposed_write, run  # noqa: E402


GUARD = Path(__file__).resolve().parent / "write_guard.py"

# Опасные строки собираются из кусков: иначе сам файл теста — это запись секрета,
# и write_guard не даст его сохранить.
LITERAL = "'" + "sk-live-0123456789abcdef" + "'"
KEY_HEADER = "-----BEGIN " + "OPENSSH PRIVATE KEY" + "-----"

CASES: list[Case] = [
    # Секрет, вписанный в код литералом, вместо чтения из окружения
    Case(
        DENY,
        "литерал вместо чтения из окружения",
        proposed_write("fixtures/settings.py", "api_key = " + LITERAL),
    ),
    Case(
        DENY,
        "литерал в правке файла",
        proposed_edit("fixtures/auth.py", "password = " + LITERAL),
    ),
    Case(
        DENY,
        "приватный ключ в тексте",
        proposed_write("fixtures/key.txt", KEY_HEADER),
    ),
    # Правильная работа с секретами: значение берётся из окружения, а не вписано в код
    Case(
        ALLOW,
        "чтение ключа из окружения",
        proposed_write("fixtures/settings.py", "api_key = os.environ[KEY_NAME]"),
    ),
    Case(
        ALLOW,
        "чтение токена из заголовка",
        proposed_write("fixtures/auth.py", "token = request.headers.get(HEADER)"),
    ),
    Case(
        ALLOW,
        "присваивание поля",
        proposed_write("fixtures/user.py", "password = user.password.strip()"),
    ),
    Case(
        ALLOW,
        "обычный код",
        proposed_write("fixtures/app.py", "def main():\n    return 0\n"),
    ),
    Case(
        ALLOW,
        "короткое значение не считается секретом",
        proposed_write("fixtures/test_config.py", "token = 'abc'"),
    ),
]


if __name__ == "__main__":
    raise SystemExit(run(GUARD, CASES, sys.argv[1:]))
