# ai-settings

Локальные инструкции для разработки этого репозитория. Общие правила для Codex,
Claude Code и других инструментов хранятся в `agent-instructions/global.md` и
передаются им только через `scripts/sync.py`.

| Область | Прочитать до работы |
| --- | --- |
| `scripts/`, генерация, синхронизация, Taskfile | `scripts/README.md` |
| конкретный guard в `hooks/` | его YAML, Python-файл, тест и `hooks/runner.py` |
| `shared/` и `include` | `scripts/config.py` |
| адаптеры инструментов | соответствующий файл в `scripts/tools/` |

## Проверки

Для изменений guard-ов использовать цикл из `scripts/README.md`:

1. `task test-plan`
2. `task generate`
3. `task test`
4. `task plan`

`task sync` применять только после отдельного подтверждения. Не править блоки
между `BEGIN AI_SETTINGS GENERATED` и `END AI_SETTINGS GENERATED` вручную.
