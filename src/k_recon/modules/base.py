"""Shared helpers for safe external process execution."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


@dataclass
class ToolRun:
    output: str = ""
    error: str | None = None
    missing: bool = False


def run_tool(name: str, args: list[str], timeout: float, input_text: str | None = None) -> ToolRun:
    executable = shutil.which(name)
    if executable is None:
        return ToolRun(error=f"{name} is not installed", missing=True)
    try:
        result = subprocess.run(
            [executable, *args],
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ToolRun(error=f"{name} exceeded the {timeout:g}s timeout")
    except OSError as exc:
        return ToolRun(error=f"could not start {name}: {exc}")
    if result.returncode:
        return ToolRun(output=result.stdout, error=result.stderr.strip() or f"{name} exited with status {result.returncode}")
    return ToolRun(output=result.stdout)


def tool_available(name: str) -> bool:
    executable = shutil.which(name)
    if executable is None:
        return False
    if name != "httpx":
        return True
    try:
        result = subprocess.run([executable, "-version"], capture_output=True, text=True, timeout=3, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    output = f"{result.stdout}\n{result.stderr}".lower()
    return result.returncode == 0 and "httpx" in output and "version" in output
