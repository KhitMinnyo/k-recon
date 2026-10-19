"""Load and validate user scope configuration."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .scope import Scope, normalize_domain


def load_scope(path: Path | None, target: str) -> Scope:
    """Load a YAML allowlist, or scope the run to the supplied target."""
    normalized_target = normalize_domain(target)
    if path is None:
        return Scope.create([normalized_target])
    try:
        raw: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"cannot read scope file {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML in scope file {path}: {exc}") from exc
    if not isinstance(raw, dict) or set(raw) - {"scope"}:
        raise ValueError("scope file must contain only a top-level 'scope' mapping")
    values = raw.get("scope")
    if not isinstance(values, dict) or set(values) - {"include", "exclude", "include_ips"}:
        raise ValueError("scope must contain only 'include', 'exclude', and 'include_ips' lists")
    include = values.get("include")
    exclude = values.get("exclude", [])
    include_ips = values.get("include_ips", [])
    if not isinstance(include, list) or not include or not all(isinstance(item, str) for item in include):
        raise ValueError("scope.include must be a non-empty list of domain names")
    if not isinstance(exclude, list) or not all(isinstance(item, str) for item in exclude):
        raise ValueError("scope.exclude must be a list of domain names")
    if not isinstance(include_ips, list) or not all(isinstance(item, str) for item in include_ips):
        raise ValueError("scope.include_ips must be a list of explicitly authorized IPs or CIDRs")
    scope = Scope.create(include, exclude, include_ips)
    if not scope.allows(normalized_target):
        raise ValueError(f"target {normalized_target!r} is not allowed by the scope file")
    return scope
