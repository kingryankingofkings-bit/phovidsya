from __future__ import annotations

from dataclasses import fields
from pathlib import Path

import yaml

from .policy import PolicyConfig


def load_policy(path: str | Path) -> PolicyConfig:
    value = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    policy = value.get("policy", {})
    allowed = {item.name for item in fields(PolicyConfig)}
    unknown = set(policy) - allowed
    if unknown:
        raise ValueError(f"unknown policy fields: {sorted(unknown)}")
    return PolicyConfig(**policy)
