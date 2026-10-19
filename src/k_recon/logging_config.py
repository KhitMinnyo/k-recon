"""Per-run console and file logging."""

from __future__ import annotations

import logging
from pathlib import Path


def configure_logging(run_dir: Path, verbose: bool = False) -> logging.Logger:
    logger = logging.getLogger(f"k_recon.{run_dir.name}")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%Y-%m-%dT%H:%M:%S")
    file_handler = logging.FileHandler(run_dir / "logs" / "recon.log", encoding="utf-8")
    file_handler.setFormatter(formatter)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    for handler in logger.handlers[:]:
        handler.close()
        logger.removeHandler(handler)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger
