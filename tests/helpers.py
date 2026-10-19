from __future__ import annotations

import logging
from pathlib import Path
from tempfile import TemporaryDirectory

from k_recon.models import RunContext
from k_recon.scope import Scope
from k_recon.storage import RunStorage


def make_context(directory: str, target: str = "example.com") -> tuple[RunContext, TemporaryDirectory[str]]:
    temporary = TemporaryDirectory(dir=directory)
    storage = RunStorage(Path(temporary.name), target)
    logger = logging.getLogger(f"test.{storage.run_dir.name}")
    logger.addHandler(logging.NullHandler())
    context = RunContext(target, Scope.create([target]), storage.run_dir, 1.0, 2, False, logger, storage)
    return context, temporary
