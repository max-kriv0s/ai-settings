"""Sync ai_settings into configured AI tools."""

from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

import yaml
from config import CONFIG_FILES, ROOT, SYNC_CONFIG, TOOL_SCRIPTS, resolve_includes
from contracts import AgentSettings, AgentsMD, Hook, Mcp, Permission, Plugin, Skill

sys.dont_write_bytecode = True
ALL_AGENTS = "all"
CONFIG_META_KEYS = {"meta"}
MODES = {"plan", "apply"}


class SyncError(RuntimeError):
    pass


@dataclass
class SyncSettings:
    agent_names: list[str]
    agent_settings: dict[str, AgentSettings]


def read_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise SyncError(f"expected mapping in YAML config: {path}")
    return resolve_includes(data)


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SyncError(f"cannot load module: {path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_sync_config(config: dict[str, Any], config_path: Path) -> None:
    tools = config.get("tools")
    if tools is None:
        raise SyncError(f"missing required key 'tools' in config: {config_path}")

    if not isinstance(tools, list):
        raise SyncError(f"'tools' must be a list in config: {config_path}")

    for tool in tools:
        if not isinstance(tool, str):
            raise SyncError(
                f"each item in 'tools' must be a string in config: {config_path}"
            )


def validate_tools_config(config: dict[str, Any], config_path: Path) -> None:
    tools = config.get("tools")
    if tools is None:
        raise SyncError(f"missing required key 'tools' in config: {config_path}")

    if not isinstance(tools, list):
        raise SyncError(f"'tools' must be a list in config: {config_path}")

    for tool in tools:
        if not isinstance(tool, str):
            raise SyncError(
                f"each item in 'tools' must be a string in config: {config_path}"
            )


def validate_enabled_config(config: dict[str, Any], config_path: Path) -> None:
    enabled = config.get("enabled")
    if enabled is None:
        raise SyncError(f"missing required key 'enabled' in config: {config_path}")

    if not isinstance(enabled, bool):
        raise SyncError(f"'enabled' must be a boolean in config: {config_path}")


def validate_skills_config(config: dict[str, Any], config_path: Path) -> None:
    skills = config.get("skills")
    if not isinstance(skills, dict):
        raise SyncError(f"'skills' must be a mapping in config: {config_path}")

    for skill_config in skills.values():
        if not isinstance(skill_config, dict):
            raise SyncError(f"skill config must be a mapping in config: {config_path}")

        validate_enabled_config(skill_config, config_path)
        validate_tools_config(skill_config, config_path)

        if not isinstance(skill_config.get("path"), str):
            raise SyncError(f"'path' must be a string in skill config: {config_path}")


def validate_settings_config(config: dict[str, Any], config_path: Path) -> None:
    for setting_name, setting_config in config.items():
        if setting_name in CONFIG_META_KEYS:
            continue

        if not isinstance(setting_config, dict):
            raise SyncError(
                f"setting config must be a mapping in config: {config_path}"
            )

        validate_enabled_config(setting_config, config_path)
        validate_tools_config(setting_config, config_path)


def read_agent_names() -> list[str]:
    config = read_yaml(SYNC_CONFIG)
    validate_sync_config(config, SYNC_CONFIG)

    tools = config.get("tools")

    names = []
    for tool in tools:
        if tool == ALL_AGENTS:
            continue

        names.append(tool)

    return names


def create_agent_settings(agent_names: list[str]) -> dict[str, AgentSettings]:
    return {agent_name: AgentSettings() for agent_name in agent_names}


def expand_agent_names(
    sync_settings: SyncSettings, raw_agent_names: list[str]
) -> list[str]:
    if ALL_AGENTS in raw_agent_names:
        return sync_settings.agent_names

    return raw_agent_names


def is_enabled(config: dict[str, Any], config_path: Path) -> bool:
    validate_enabled_config(config, config_path)
    return config["enabled"]


def read_tools(config: dict[str, Any], config_path: Path) -> list[str]:
    validate_tools_config(config, config_path)
    return config["tools"]


def setting_config_without_routing(config: dict[str, Any]) -> dict[str, Any]:
    result = {}
    for key, value in config.items():
        if key in {"enabled", "tools"}:
            continue
        result[key] = value
    return result


def add_agent_setting(
    sync_settings: SyncSettings,
    agent_name: str,
    section_name: str,
    setting: Any,
) -> None:
    agent_settings = sync_settings.agent_settings.get(agent_name)
    if agent_settings is None:
        raise SyncError(f"unknown agent '{agent_name}'")

    section = getattr(agent_settings, section_name)
    section.append(setting)


def add_agent_settings(
    sync_settings: SyncSettings,
    agent_names: list[str],
    section_name: str,
    setting: Any,
) -> None:
    for agent_name in agent_names:
        add_agent_setting(sync_settings, agent_name, section_name, setting)


def load_agents_settings(sync_settings: SyncSettings) -> None:
    agents_md = AgentsMD(
        source_path=ROOT / "AGENTS.md",
        include_path=f"~/{(ROOT / 'AGENTS.md').relative_to(Path.home())}",
    )

    for agent_name in sync_settings.agent_names:
        sync_settings.agent_settings[agent_name].agentsMD = agents_md


def load_skills_settings(sync_settings: SyncSettings) -> None:
    config_path = CONFIG_FILES["skills"]
    config = read_yaml(config_path)
    validate_skills_config(config, config_path)
    skills = config.get("skills")

    for skill_name, skill_config in skills.items():
        if not is_enabled(skill_config, config_path):
            continue

        skill_path = skill_config.get("path")
        skill = Skill(
            skill_id=skill_name,
            path=ROOT.parent / skill_path,
            description=skill_config.get("description", ""),
        )

        tools = read_tools(skill_config, config_path)
        agent_names = expand_agent_names(sync_settings, tools)

        add_agent_settings(sync_settings, agent_names, "skills", skill)


def load_named_settings(
    sync_settings: SyncSettings,
    config_key: str,
    target_field: str,
    item_class: type[Permission] | type[Mcp] | type[Plugin] | type[Hook],
) -> None:
    config_path = CONFIG_FILES[config_key]
    config = read_yaml(config_path)
    validate_settings_config(config, config_path)

    for setting_name, setting_config in config.items():
        if setting_name in CONFIG_META_KEYS:
            continue

        if not is_enabled(setting_config, config_path):
            continue

        item = item_class(
            name=setting_name,
            config=setting_config_without_routing(setting_config),
        )

        tools = read_tools(setting_config, config_path)
        agent_names = expand_agent_names(sync_settings, tools)

        add_agent_settings(sync_settings, agent_names, target_field, item)


def load_permissions_settings(sync_settings: SyncSettings) -> None:
    load_named_settings(sync_settings, "permissions", "permissions", Permission)


def load_mcp_settings(sync_settings: SyncSettings) -> None:
    load_named_settings(sync_settings, "mcp", "mcp", Mcp)


def load_plugins_settings(sync_settings: SyncSettings) -> None:
    load_named_settings(sync_settings, "plugins", "plugins", Plugin)


def load_hooks_settings(sync_settings: SyncSettings) -> None:
    load_named_settings(sync_settings, "hooks", "hooks", Hook)


def sync_codex(sync_settings: SyncSettings, mode: str) -> None:
    agent_settings = sync_settings.agent_settings.get("codex")
    if agent_settings is None:
        return

    adapter_path = ROOT / "scripts" / TOOL_SCRIPTS["codex"]
    adapter = load_module(adapter_path, "ai_settings_codex")
    adapter.sync(agent_settings, mode)


def sync_claude(sync_settings: SyncSettings, mode: str) -> None:
    agent_settings = sync_settings.agent_settings.get("claude")
    if agent_settings is None:
        return

    adapter_path = ROOT / "scripts" / TOOL_SCRIPTS["claude"]
    adapter = load_module(adapter_path, "ai_settings_claude")
    adapter.sync(agent_settings, mode)


def read_mode(argv: list[str]) -> str:
    if not argv:
        return "apply"

    if len(argv) != 1:
        raise SyncError("expected at most one argument: plan or apply")

    mode = argv[0]
    if mode not in MODES:
        raise SyncError(f"unknown mode: {mode}")

    return mode


def main() -> int:
    mode = read_mode(sys.argv[1:])
    agent_names = read_agent_names()
    agent_settings = create_agent_settings(agent_names)

    sync_settings = SyncSettings(
        agent_names=agent_names,
        agent_settings=agent_settings,
    )

    load_agents_settings(sync_settings)
    load_skills_settings(sync_settings)
    load_permissions_settings(sync_settings)
    load_mcp_settings(sync_settings)
    load_plugins_settings(sync_settings)
    load_hooks_settings(sync_settings)

    sync_codex(sync_settings, mode)
    sync_claude(sync_settings, mode)

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SyncError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
