---
name: obsidian-cli
description: "Use when working with the user Obsidian vault llm_wiki through the native Obsidian CLI: reading, searching, creating, editing, moving, deleting, inspecting notes, or preserving non-Markdown files."
type: ai/skill
status: draft
tags:
  - "#ai/skill"
project: llm_wiki
related:
tools:
  - obsidian-cli
---

# Obsidian CLI

Используй этот skill для работы с Obsidian vault `llm_wiki`.

## Базовое правило

Всегда обращайся к vault по имени:

```bash
obsidian <command> ... vault=llm_wiki
```

Не используй абсолютный путь к vault в рабочих командах. Расположением vault управляет Obsidian.

Исключение: если текст большой или правка через CLI неудобна, сразу правь файл в каталоге vault напрямую. Корневой путь — `obsidian vault info=path vault=llm_wiki`, Obsidian подхватит изменения сам.

## Типовые команды

- Проверить vault: `obsidian vault info=name vault=llm_wiki`
- Список файлов: `obsidian files vault=llm_wiki`
- Список папок: `obsidian folders vault=llm_wiki`
- Прочитать файл: `obsidian read path=<path> vault=llm_wiki`
- Поиск: `obsidian search query=<text> vault=llm_wiki`
- Создать markdown-файл: `obsidian create path=<path> content=<text> vault=llm_wiki`
- Добавить текст: `obsidian append path=<path> content=<text> vault=llm_wiki`
- Переместить или переименовать: `obsidian move path=<path> to=<path> vault=llm_wiki`
- Удалять только после явного подтверждения пользователя: `obsidian delete path=<path> vault=llm_wiki`

## Правка существующих заметок

Команды точечной замены текста (`replace`, `edit`, `patch`) в CLI нет. Менять содержимое существующей заметки можно только так:

- Чекбоксы и пункты чек-листов: `obsidian task path=<path> line=<n> done vault=llm_wiki`. Вместо `done` доступны `todo`, `toggle` и `status="<char>"` для произвольного символа статуса. Строку можно задать как `ref=<path:line>` вместо пары `path` + `line`.
- Найти нужные строки перед правкой: `obsidian tasks path=<path> verbose vault=llm_wiki` — выводит задачи с номерами строк, есть фильтры `todo`, `done`, `format=json`.
- Frontmatter: `obsidian property:set path=<path> name=<name> value=<value> vault=llm_wiki`, при необходимости `type=text|list|number|checkbox|date|datetime`. Удалить — `obsidian property:remove`.
- Дописать в конец или начало: `obsidian append` и `obsidian prepend`.
- Заменить файл целиком: `obsidian create path=<path> content=<text> overwrite vault=llm_wiki`.
- Заменить фрагмент в середине файла: правь файл напрямую либо через `obsidian eval`, см. ниже. Учитывай, что `eval` вычисляет код как скрипт, а не как модуль, поэтому top-level `await` там запрещён — используй цепочку `.then(...)` либо оборачивай в `(async () => { ... })()` и возвращай результат.

## Файлы не Markdown

Для настоящих `.toml`, `.py` и других non-Markdown файлов команда `create path=...` может создать markdown-note. Если важно сохранить точное расширение, используй:

```bash
obsidian eval code=<javascript> vault=llm_wiki
```

и внутри JavaScript записывай файл через `app.vault.adapter.write(path, content)`.

## Ссылки Obsidian

Когда создаёшь или редактируешь навигационные Markdown-файлы внутри vault, используй Obsidian wikilinks вместо обычных текстовых путей:

```markdown
[[ai_settings/docs/sync|Команды sync.py]]
```

Формат:

- `[[path/to/file|Красивое имя]]` - ссылка с произвольным текстом.
- `[[path/to/file]]` - ссылка без отдельного текста.

Для существующих файлов указывай путь внутри vault без абсолютного пути. После правки навигации проверяй ссылки через:

```bash
obsidian links path=<path> vault=llm_wiki
```

## Перенос строк внутри абзаца

Одиночный перевод строки внутри абзаца Obsidian показывает как видимый разрыв. Не оборачивай абзацы и пункты списка вручную по ширине — один абзац/пункт = одна строка в файле.

## Безопасность

- Не запускай bare `obsidian`.
- Не обращайся к другим vault.
- Перед изменениями сначала читай текущий файл или проверяй структуру.
- Не перезаписывай и не удаляй без явного подтверждения пользователя.
- Не создавай README в каждой папке ради самой папки; README нужен только там, где он реально помогает навигации.
