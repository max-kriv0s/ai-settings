"""Zed-specific renderer for universal ai_settings policies."""

from __future__ import annotations

from typing import Any


def not_implemented(
    section: str, name: str, source: str, target: str
) -> dict[str, str]:
    return {
        "section": section,
        "name": name,
        "tool": "zed",
        "action": "not_implemented",
        "source": source,
        "target": target,
        "reason": "Zed renderer stub is present, but sync rendering is not implemented yet.",
    }


def build_plan(state: Any, section: str) -> list[dict[str, str]]:
    plan: list[dict[str, str]] = []
    if section in {"all", "agents"} and state.agentsMD is not None:
        plan.append(
            not_implemented(
                "agents",
                "AGENTS.md",
                str(state.agentsMD.source_path),
                "zed agent rules",
            )
        )
    if section in {"all", "skills"} and state.skills:
        plan.append(
            not_implemented(
                "skills", "skills.yaml", "ai_settings/skills/skills.yaml", "zed skills"
            )
        )
    if section in {"all", "permissions"} and state.permissions is not None:
        plan.append(
            not_implemented(
                "permissions",
                "policy.yaml",
                "ai_settings/permissions/policy.yaml",
                "zed permissions",
            )
        )
    if section in {"all", "hooks"} and state.hooks is not None:
        plan.append(
            not_implemented(
                "hooks", "hooks.yaml", "ai_settings/hooks/hooks.yaml", "zed hooks"
            )
        )
    if section in {"all", "mcp"} and state.mcp is not None:
        plan.append(
            not_implemented(
                "mcp", "profiles.yaml", "ai_settings/mcp/profiles.yaml", "zed mcp"
            )
        )
    if section in {"all", "plugins"} and state.plugins is not None:
        plan.append(
            not_implemented(
                "plugins",
                "policy.yaml",
                "ai_settings/plugins/policy.yaml",
                "zed plugins",
            )
        )
    return plan


def apply_plan_item(plan: dict[str, str]) -> None:
    raise RuntimeError(f"Zed apply is not implemented for section: {plan['section']}")
