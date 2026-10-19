"""Shared domain models used by modules and the runner."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from k_recon.scope import Scope
    from k_recon.storage import RunStorage

ModuleState = Literal["success", "partial", "failed", "skipped"]


@dataclass
class ModuleResult:
    name: str
    state: ModuleState
    message: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class RunContext:
    target: str
    scope: Scope
    run_dir: Path
    timeout: float
    workers: int
    enable_nmap: bool
    logger: logging.Logger
    storage: RunStorage
    data: dict[str, Any] = field(default_factory=dict)
