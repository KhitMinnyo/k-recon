"""Explicitly enabled Nmap adapter restricted to IPs listed in the scope file."""

from __future__ import annotations

from k_recon.models import ModuleResult, RunContext
from k_recon.modules.base import run_tool


def run(context: RunContext) -> ModuleResult:
    if not context.enable_nmap:
        return ModuleResult("ports", "skipped", "Nmap requires the explicit --enable-nmap flag")

    resolved = {
        address
        for record in context.data.get("dns_records", [])
        if record.get("safe_for_network_modules") and context.scope.allows(str(record.get("host", "")))
        for address in record.get("public_addresses", [])
        if context.scope.allows_ip(str(address))
    }
    if not resolved:
        message = "No public resolved IPs were explicitly authorized in scope.include_ips"
        context.logger.warning(message)
        context.storage.write_text("scans/nmap.txt", f"{message}\n")
        return ModuleResult("ports", "partial", message, {"targets": 0})

    target_file = context.storage.write_lines("scans/nmap-targets.txt", resolved)
    output_file = context.storage.path("scans/nmap.txt")
    args = ["-n", "-iL", str(target_file), "-T4", "-p-", "-sV", "-oN", str(output_file)]
    result = run_tool("nmap", args, context.timeout * max(1, len(resolved)))
    if result.error:
        context.logger.error("Nmap failed: %s", result.error)
        context.storage.write_text("scans/nmap-error.txt", result.error + "\n")
        return ModuleResult("ports", "failed", result.error, {"targets": len(resolved)})
    context.logger.info("Nmap completed for %d explicitly authorized IP(s)", len(resolved))
    return ModuleResult("ports", "success", "Nmap scan completed", {"targets": len(resolved)})
