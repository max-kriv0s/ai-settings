---
type: wiki/doc
status: draft
tags:
  - "#wiki/doc"
project: llm_wiki
related:
---

created_at: `= this.file.ctime` · updated_at: `= this.file.mtime`

# AI Settings

Единое место для настроек ИИ-инструментов и скриптов, которые синхронизируют эти настройки в Codex, Claude Code, Zed и другие инструменты.

## Разделы

- permissions/ - универсальная политика разрешений и запретов.
- skills/ - описания персональных навыков и правила их установки.
- mcp/ - профили MCP и правила подключения серверов.
- plugins/ - политика плагинов и доверия к ним.
- hooks/ - правила lifecycle hooks.
- scripts/ - общий sync-скрипт и tool-specific реализация.
- docs/ - пояснения, инструкции и проектные заметки по ai_settings.

## Основной принцип

Файлы в этом разделе описывают намерение в универсальном виде. Уникальность Codex, Claude Code, Zed и других инструментов должна жить в scripts/tools/, а не в общей политике.
