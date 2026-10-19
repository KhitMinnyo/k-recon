"""Run-isolated, atomic artifact storage."""

from __future__ import annotations

import json
import os
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .scope import normalize_domain


class RunStorage:
    def __init__(self, output: Path, target: str) -> None:
        self.target = normalize_domain(target)
        self.target_dir = output.expanduser() / self.target
        self.runs_dir = self.target_dir / "runs"
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        while True:
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            run_id = f"{stamp}-{uuid.uuid4().hex[:8]}"
            self.run_dir = self.runs_dir / run_id
            try:
                self.run_dir.mkdir()
                break
            except FileExistsError:
                continue

    def path(self, *parts: str) -> Path:
        if any(Path(part).is_absolute() or ".." in Path(part).parts for part in parts):
            raise ValueError("artifact paths must remain inside the current run")
        result = self.run_dir.joinpath(*parts)
        result.parent.mkdir(parents=True, exist_ok=True)
        return result

    def write_text(self, relative: str, text: str) -> Path:
        return self._atomic_write(self.path(relative), text)

    def write_json(self, relative: str, value: Any) -> Path:
        return self.write_text(relative, json.dumps(value, indent=2, sort_keys=True, default=str) + "\n")

    def write_lines(self, relative: str, values: Iterable[str]) -> Path:
        return self.write_text(relative, "".join(f"{value}\n" for value in sorted(set(values))))

    @staticmethod
    def _atomic_write(path: Path, text: str) -> Path:
        file_descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
        try:
            with os.fdopen(file_descriptor, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(text)
            os.replace(temporary, path)
        except BaseException:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise
        return path
