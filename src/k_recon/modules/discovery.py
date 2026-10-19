"""Subdomain discovery adapters for Subfinder, Assetfinder, and Amass."""

from __future__ import annotations

from k_recon.models import ModuleResult, RunContext
from k_recon.modules.base import run_tool


PROVIDERS = {
    "subfinder": ("subfinder", ["-d", "{target}", "-silent"]),
    "assetfinder": ("assetfinder", ["--subs-only", "{target}"]),
    "amass": ("amass", ["enum", "-passive", "-d", "{target}"]),
}


def run(context: RunContext) -> ModuleResult:
    accepted = {context.target}
    provider_report: dict[str, dict[str, object]] = {}
    failed = False
    completed = False
    rejected_count = 0

    for provider, (executable, template) in PROVIDERS.items():
        context.storage.write_lines(f"subdomains/{provider}.txt", [])
        args = [value.format(target=context.target) for value in template]
        result = run_tool(executable, args, context.timeout)
        if result.error:
            provider_report[provider] = {"state": "missing" if result.missing else "failed", "error": result.error}
            context.logger.warning("Discovery provider %s: %s", provider, result.error)
            failed = failed or not result.missing
            continue

        hosts, rejected = context.scope.filter(result.output.splitlines())
        rejected_count += len(rejected)
        accepted.update(hosts)
        provider_report[provider] = {"state": "success", "count": len(hosts)}
        context.storage.write_lines(f"subdomains/{provider}.txt", hosts)
        context.logger.info("%s returned %d in-scope host(s)", provider, len(hosts))
        completed = True

    hosts = sorted(accepted)
    context.storage.write_lines("subdomains/all.txt", hosts)
    context.storage.write_json("subdomains/providers.json", provider_report)
    context.data["hosts"] = hosts
    context.data["discovery_complete"] = completed
    context.logger.info("Discovery retained %d unique in-scope host(s)", len(hosts))

    if failed:
        state = "partial"
    elif not completed:
        state = "partial"
    else:
        state = "success"
    return ModuleResult(
        "discovery",
        state,
        "Discovery completed with provider warnings" if state == "partial" else "Discovery completed",
        {"hosts": len(hosts), "rejected": rejected_count, "providers": provider_report},
    )
