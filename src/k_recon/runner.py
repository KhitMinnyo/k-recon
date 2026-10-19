"""Dependency-aware orchestration for reconnaissance modules."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from k_recon.logging_config import configure_logging
from k_recon.models import ModuleResult, RunContext
from k_recon.modules import discovery, dns, http, ports, screenshots, urls
from k_recon.scope import Scope, normalize_domain
from k_recon.storage import RunStorage

MODULES: dict[str, Callable[[RunContext], ModuleResult]] = {
    "discovery": discovery.run,
    "dns": dns.run,
    "http": http.run,
    "screenshots": screenshots.run,
    "urls": urls.run,
    "ports": ports.run,
}
DEPENDENCIES: dict[str, tuple[str, ...]] = {
    "discovery": (),
    "dns": ("discovery",),
    "http": ("dns",),
    "screenshots": ("http",),
    "urls": ("discovery",),
    "ports": ("dns",),
}
ORDER = tuple(MODULES)


class ScanInterrupted(Exception):
    """Raised after an interrupted run has written its partial report."""

    def __init__(self, run_dir: Path) -> None:
        super().__init__("scan interrupted")
        self.run_dir = run_dir


def resolve_plan(selected: list[str]) -> list[str]:
    unknown = sorted(set(selected) - MODULES.keys())
    if unknown:
        raise ValueError(f"unknown module(s): {', '.join(unknown)}")
    planned = set(selected)

    def add_dependencies(name: str) -> None:
        for dependency in DEPENDENCIES[name]:
            if dependency not in planned:
                planned.add(dependency)
                add_dependencies(dependency)

    for name in list(planned):
        add_dependencies(name)
    return [name for name in ORDER if name in planned]


def run_scan(
    target: str,
    scope: Scope,
    output: Path,
    selected: list[str],
    timeout: float,
    workers: int,
    enable_nmap: bool,
    verbose: bool = False,
) -> tuple[Path, list[ModuleResult]]:
    normalized_target = normalize_domain(target)
    if not scope.allows(normalized_target):
        raise ValueError(f"target {normalized_target!r} is outside the configured scope")
    plan = resolve_plan(selected)
    storage = RunStorage(output, normalized_target)
    (storage.run_dir / "logs").mkdir(parents=True, exist_ok=True)
    logger = configure_logging(storage.run_dir, verbose)
    context = RunContext(
        target=normalized_target,
        scope=scope,
        run_dir=storage.run_dir,
        timeout=timeout,
        workers=workers,
        enable_nmap=enable_nmap,
        logger=logger,
        storage=storage,
    )
    storage.write_text(
        "scope.txt",
        "In-scope domains:\n"
        + "".join(f"  {domain}\n" for domain in scope.include)
        + "Excluded domains:\n"
        + "".join(f"  {domain}\n" for domain in scope.exclude)
        + "Explicitly authorized Nmap IPs/CIDRs:\n"
        + "".join(f"  {network}\n" for network in scope.include_ips),
    )
    logger.info("Starting run for %s", normalized_target)
    logger.info("Selected module plan: %s", ", ".join(plan))
    logger.debug("Run settings: timeout=%s workers=%s nmap=%s", timeout, workers, enable_nmap)

    results: list[ModuleResult] = []
    states: dict[str, str] = {}
    started = datetime.now(timezone.utc)
    interrupted = False
    for index, name in enumerate(plan):
        failed_dependencies = [dependency for dependency in DEPENDENCIES[name] if states.get(dependency) in ("failed", "skipped")]
        if failed_dependencies:
            result = ModuleResult(name, "skipped", f"Required module(s) did not complete: {', '.join(failed_dependencies)}")
        else:
            logger.info("Starting module: %s", name)
            try:
                result = MODULES[name](context)
            except KeyboardInterrupt:
                logger.warning("Scan interrupted during module %s", name)
                result = ModuleResult(name, "skipped", "Interrupted by user")
                interrupted = True
            except Exception as exc:
                logger.exception("Module %s failed", name)
                result = ModuleResult(name, "failed", str(exc))
            logger.info("Module %s: %s - %s", name, result.state, result.message)
        results.append(result)
        states[name] = result.state
        if interrupted:
            for pending in plan[index + 1:]:
                skipped = ModuleResult(pending, "skipped", "Not started because the scan was interrupted")
                results.append(skipped)
                states[pending] = skipped.state
            break

    finished = datetime.now(timezone.utc)
    report = {
        "target": normalized_target,
        "run_id": storage.run_dir.name,
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "interrupted": interrupted,
        "selected_modules": plan,
        "modules": [
            {"name": item.name, "state": item.state, "message": item.message, "details": item.details}
            for item in results
        ],
    }
    storage.write_json("report.json", report)
    logger.info("Run artifacts: %s", storage.run_dir)
    if interrupted:
        raise ScanInterrupted(storage.run_dir)
    return storage.run_dir, results
