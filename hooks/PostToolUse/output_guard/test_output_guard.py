"""Smoke checks for output_guard. See hooks/runner.py — nothing here is executed.

DENY-кейсы с настоящим секретом в тексте агент вставить не может: их блокирует
write_guard при записи этого файла. Они добавляются человеком.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from runner import ALLOW, DENY, Case, run, tool_output  # noqa: E402

GUARD = Path(__file__).resolve().parent / "output_guard.py"

# Опасные строки собираются из кусков: иначе сам файл теста — это запись секрета,
# и write_guard не даст его сохранить.
KEY_HEADER = "-----BEGIN " + "OPENSSH PRIVATE KEY" + "-----"
LEAKED = "AWS_SECRET" + "_ACCESS_KEY=" + "wJalrXUtnFEMI0123456789"
ENV_FILE = "." + "env"
LOCAL_ENV_FILE = ENV_FILE + ".local"

CASES: list[Case] = [
    # Секрет в самом выводе, а не имя файла
    Case(
        DENY,
        "приватный ключ в выводе",
        tool_output(KEY_HEADER + "\nb3BlbnNzaC1rZXk=\n"),
    ),
    Case(DENY, "значение секрета без кавычек", tool_output(LEAKED)),
    Case(DENY, "вывод содержит .env.local", tool_output("config/.env.local\n")),
    Case(DENY, "путь внутри каталога ключей", tool_output("/home/user/.ssh/config\n")),
    # Вывод называет файл, который не должен читаться
    Case(DENY, "вывод содержит .env", tool_output("total 8\n.env\nREADME.md\n")),
    Case(
        DENY,
        "вывод содержит credentials",
        tool_output("fixtures/home/.aws/credentials"),
    ),
    Case(DENY, "вывод содержит имя ключа", tool_output("fixtures/keys/id_rsa")),
    # Обычный вывод
    Case(ALLOW, "листинг проекта", tool_output("README.md\npyproject.toml\nscripts\n")),
    Case(ALLOW, "шаблон окружения", tool_output(".env.example\n")),
    Case(ALLOW, "структурированный ответ", tool_output({"ok": True, "files": 3})),
    Case(ALLOW, "пустой ответ", tool_output("")),
    Case(ALLOW, "код с переменной", tool_output("value = compute(payload)")),
    Case(
        ALLOW,
        "исходник упоминает запрещённый путь",
        tool_output("config/" + LOCAL_ENV_FILE + "\n", command="sed -n '1p' policy.py"),
    ),
    Case(
        DENY,
        "путь в выводе конвейера",
        tool_output("config/" + LOCAL_ENV_FILE + "\n", command="cat script.sh | bash"),
    ),
    Case(
        DENY,
        "секрет при чтении исходника",
        tool_output(LEAKED, command="sed -n '1p' policy.py"),
    ),
]


if __name__ == "__main__":
    raise SystemExit(run(GUARD, CASES, sys.argv[1:]))
