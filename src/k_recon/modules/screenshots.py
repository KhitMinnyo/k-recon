"""Optional GoWitness screenshot capture for validated live services."""

from __future__ import annotations

from k_recon.models import ModuleResult, RunContext
from k_recon.modules.base import run_tool


def run(context: RunContext) -> ModuleResult:
    services = context.data.get("services", [])
    urls = sorted({
        str(service["url"])
        for service in services
        if service.get("status_code") is not None
        and not 300 <= int(service["status_code"]) < 400
        and context.scope.allows(str(service.get("host", "")))
        and context.scope.allows_url(str(service["url"]))
    })
    screenshot_dir = context.storage.path("screenshots")
    screenshot_dir.mkdir(parents=True, exist_ok=True)
    context.storage.write_lines("screenshots/targets.txt", urls)
    if not urls:
        return ModuleResult("screenshots", "partial", "No eligible live URLs were available for screenshots", {"targets": 0})

    result = run_tool(
        "gowitness",
        ["scan", "file", "--file", str(context.storage.path("screenshots/targets.txt")), "--screenshot-path", str(screenshot_dir), "--no-http"],
        context.timeout * max(1, len(urls)),
    )
    if result.error:
        context.logger.warning("Screenshot module: %s", result.error)
        return ModuleResult("screenshots", "partial", result.error, {"targets": len(urls)})
    context.logger.info("GoWitness processed %d validated URL(s)", len(urls))
    return ModuleResult("screenshots", "success", "Screenshot capture completed", {"targets": len(urls)})
