"""Shared settings contracts passed from sync.py to tool adapters."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class AgentsMD:
    source_path: Path
    include_path: str


@dataclass
class Skill:
    skill_id: str
    path: Path
    description: str = ""


@dataclass
class Permission:
    name: str
    config: dict[str, Any] = field(default_factory=dict)


@dataclass
class Mcp:
    name: str
    config: dict[str, Any] = field(default_factory=dict)


@dataclass
class Plugin:
    name: str
    config: dict[str, Any] = field(default_factory=dict)


@dataclass
class Hook:
    name: str
    config: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentSettings:
    agentsMD: AgentsMD | None = None
    skills: list[Skill] = field(default_factory=list)
    permissions: list[Permission] = field(default_factory=list)
    mcp: list[Mcp] = field(default_factory=list)
    plugins: list[Plugin] = field(default_factory=list)
    hooks: list[Hook] = field(default_factory=list)
