---
type: wiki/doc
status: draft
tags:
  - "#wiki/doc"
project: llm_wiki
related:
---

created_at: `= this.file.ctime` · updated_at: `= this.file.mtime`

# sync.py

Главный скрипт синхронизации `ai_settings` в настройки ИИ-инструментов.

## Базовая модель

Конфиги в `ai_settings` описывают, что должно быть подключено. Скрипт сам
определяет целевые инструменты по YAML-файлам. В обычном сценарии не нужно
указывать `codex`, `claude`, `zed` или `pi` руками.

В `sync.py` есть явный registry поддерживаемых инструментов:

```python
TOOL_SCRIPTS = {
    "codex": Path("tools/codex.py"),
    "claude": Path("tools/claude.py"),
    "zed": Path("tools/zed.py"),
    "pi": Path("tools/pi.py"),
}
```

Скрипт идёт по этому списку, создаёт `ToolSyncState` для каждого инструмента,
добавляет в него настройки из YAML-секций и вызывает адаптер только если для
инструмента есть настройки для синхронизации.

Если настройки есть, но адаптер отсутствует или ещё не реализует нужный
интерфейс, план показывает `adapter_missing` или `not_implemented` и не
применяет изменения молча.

## Команды

Показать план по всему:

```bash
python3 ai_settings/scripts/sync.py
```

Применить весь план:

```bash
python3 ai_settings/scripts/sync.py apply
```

Показать план подключения общих AGENTS-правил:

```bash
python3 ai_settings/scripts/sync.py agents
```

Применить подключение общих AGENTS-правил:

```bash
python3 ai_settings/scripts/sync.py apply agents
```

Показать план только по skills:

```bash
python3 ai_settings/scripts/sync.py skills
```

Показать план только по одному skill:

```bash
python3 ai_settings/scripts/sync.py skills obsidian-cli
```

Применить только один skill:

```bash
python3 ai_settings/scripts/sync.py apply skills obsidian-cli
```

## Правила аргументов

- Без аргументов выполняется `plan all`.
- `plan`, `apply`, `check` - режимы. Сейчас реализованы `plan` и `apply`.
- `agents`, `skills`, `permissions`, `mcp`, `plugins`, `hooks` - фильтры
  разделов. Сейчас реализованы `agents` и `skills`.
- Третий аргумент уточняет конкретный объект, например `obsidian-cli`.
- Целевые инструменты берутся из `tools` в соответствующем YAML-файле или разделе.

## Текущий статус

Сейчас скрипт умеет подключать общие Codex AGENTS-правила через managed block в
начале `~/.codex/AGENTS.md`, а также Codex skills через symlink из vault в
`~/.codex/skills`. Claude Code, Zed и pi распознаются как известные
инструменты, но их синхронизация ещё не реализована.

Следующий шаг - добавить loaders для `permissions`, `hooks`, `mcp` и `plugins`,
чтобы они наполняли тот же `ToolSyncState`, а не обрабатывались отдельными
ветками.
