"""Historical URL collection using Waybackurls and/or gau."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from k_recon.models import ModuleResult, RunContext
from k_recon.modules.base import run_tool

PROVIDERS = ("waybackurls", "gau")


def run(context: RunContext) -> ModuleResult:
    hosts = sorted({host for host in context.data.get("hosts", [context.target]) if context.scope.allows(host)})
    all_urls: set[str] = set()
    provider_status: dict[str, dict[str, object]] = {}
    had_failure = False
    had_provider = False

    for provider in PROVIDERS:
        context.storage.write_lines(f"urls/{provider}.txt", [])
        args = ["--subs"] if provider == "gau" else []
        result = run_tool(provider, args, context.timeout * 3, "".join(f"{host}\n" for host in hosts))
        if result.error:
            provider_status[provider] = {"state": "missing" if result.missing else "failed", "error": result.error}
            context.logger.warning("URL provider %s: %s", provider, result.error)
            had_failure = had_failure or not result.missing
            continue

        accepted: set[str] = set()
        rejected = 0
        for line in result.output.splitlines():
            url = line.strip()
            try:
                if not context.scope.allows_url(url):
                    rejected += 1
                    continue
                accepted.add(url)
            except ValueError:
                rejected += 1
        all_urls.update(accepted)
        context.storage.write_lines(f"urls/{provider}.txt", accepted)
        provider_status[provider] = {"state": "success", "count": len(accepted), "rejected": rejected}
        had_provider = True
        context.logger.info("%s returned %d in-scope URL(s)", provider, len(accepted))

    parameters = {
        f"{urlsplit(url).scheme}://{urlsplit(url).netloc}{urlsplit(url).path}?{name}="
        for url in all_urls
        for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)
    }
    extensions: dict[str, set[str]] = {suffix: set() for suffix in ("js", "html", "json", "php", "aspx", "jsp")}
    for url in all_urls:
        suffix = Path(urlsplit(url).path).suffix.lower().lstrip(".")
        if suffix in extensions:
            extensions[suffix].add(url)
    context.storage.write_lines("urls/all.txt", all_urls)
    context.storage.write_lines("urls/parameters.txt", parameters)
    for suffix, entries in extensions.items():
        context.storage.write_lines(f"urls/extensions/{suffix}.txt", entries)
    context.storage.write_json("urls/providers.json", provider_status)
    context.data["urls"] = sorted(all_urls)
    context.data["parameters"] = sorted(parameters)

    state = "partial" if had_failure or not had_provider else "success"
    return ModuleResult(
        "urls",
        state,
        "URL collection completed with provider warnings" if state == "partial" else "URL collection completed",
        {"urls": len(all_urls), "parameters": len(parameters), "providers": provider_status},
    )
