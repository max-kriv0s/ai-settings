---
type: wiki/doc
status: draft
tags:
  - "#wiki/doc"
project: llm_wiki
related:
---

created_at: `= this.file.ctime` · updated_at: `= this.file.mtime`

# scripts

Скрипты синхронизации `ai_settings` с настройками инструментов.

## Архитектура sync

`ai_settings` хранит общие правила в YAML-файлах. Эти файлы не являются
tool-specific конфигами: они описывают намерение один раз, а `sync.py`
маршрутизирует его по инструментам.

Справочник допустимых инструментов живет только в
`ai_settings/scripts/sync.yaml`. В остальных YAML-файлах верхнеуровневый
`tools` не дублируется.

Каждый настраиваемый раздел начинается с `enabled` и `tools`:

```yaml
read_policy:
  enabled: true
  tools:
    - all
```

`enabled: false` отключает раздел. Значение `all` понимает только `sync.py`: он
разворачивает его во все конкретные инструменты из `scripts/sync.yaml`.

Если в YAML указан инструмент, которого нет в `TOOL_SCRIPTS`, `sync.py` должен
завершиться ошибкой. Это защищает от молчаливого пропуска правил.

Порядок работы:

1. `sync.py` читает общие YAML-файлы.
2. `sync.py` собирает отдельный `ToolSyncState` для каждого инструмента.
3. В `ToolSyncState` попадают только правила, которые относятся к этому
   инструменту: напрямую или через `all`.
4. `sync.py` находит adapter в `TOOL_SCRIPTS` и передает ему уже готовый
   per-tool state.
5. Adapter (`tools/codex.py`, `tools/claude.py`, `tools/zed.py`, `tools/pi.py`)
   ничего не знает про `all` и другие инструменты. Он получает только свои
   `agents`, `skills`, `permissions`, `hooks`, `mcp`, `plugins` и рендерит их в
   формат своего клиента.

`AGENTS.md` тоже проходит через эту модель. Каждый adapter сам решает, как
подключать общий файл: symlink, include, `@AGENTS.md` или другой механизм
конкретного инструмента.

## Проверки Python

Не создавать `__pycache__` и `.pyc`.

Для проверки синтаксиса использовать команды без записи байткода:

```bash
python3 -B -c 'import ast, pathlib; ast.parse(pathlib.Path("ai_settings/scripts/sync.py").read_text())'
```

Не использовать:

```bash
python3 -m py_compile ...
```
