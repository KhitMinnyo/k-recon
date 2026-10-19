"""HTTP probing using httpx when available, with a standard-library fallback."""

from __future__ import annotations

import concurrent.futures
import http.client
import html.parser
import json
import socket
import ssl
from dataclasses import asdict, dataclass
from urllib.parse import urlsplit

from k_recon.models import ModuleResult, RunContext
from k_recon.modules.base import run_tool, tool_available


@dataclass
class Service:
    url: str
    host: str
    status_code: int | None = None
    title: str = ""
    content_type: str = ""
    server: str = ""
    error: str | None = None


class _TitleParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.active = False
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.active = tag.lower() == "title"

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.active = False

    def handle_data(self, data: str) -> None:
        if self.active:
            self.parts.append(data)


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, address: str, port: int, timeout: float) -> None:
        super().__init__(host, port=port, timeout=timeout)
        self.address = address

    def connect(self) -> None:
        self.sock = socket.create_connection((self.address, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, address: str, port: int, timeout: float) -> None:
        super().__init__(host, port=port, timeout=timeout, context=ssl.create_default_context())
        self.address = address

    def connect(self) -> None:
        raw_socket = socket.create_connection((self.address, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)


def _native_probe(host: str, addresses: list[str], timeout: float) -> Service:
    last_error = "connection failed"
    for scheme in ("https", "http"):
        port = 443 if scheme == "https" else 80
        for address in addresses:
            connection: http.client.HTTPConnection
            if scheme == "https":
                connection = _PinnedHTTPSConnection(host, address, port, timeout)
            else:
                connection = _PinnedHTTPConnection(host, address, port, timeout)
            url = f"{scheme}://{host}/"
            try:
                connection.request("GET", "/", headers={"Host": host, "User-Agent": "k-recon/0.1 authorized-security-assessment", "Connection": "close"})
                response = connection.getresponse()
                body = response.read(65536).decode("utf-8", errors="replace")
                parser = _TitleParser()
                parser.feed(body)
                return Service(url, host, response.status, " ".join("".join(parser.parts).split()), response.getheader("Content-Type", ""), response.getheader("Server", ""))
            except (OSError, http.client.HTTPException, ssl.SSLError, ValueError) as exc:
                last_error = str(exc)
            finally:
                connection.close()
    return Service(f"https://{host}/", host, error=last_error)


def _httpx_probe(context: RunContext, hosts: list[str]) -> tuple[list[Service], str | None]:
    args = [
        "-json", "-silent", "-no-color", "-status-code", "-title", "-tech-detect",
        "-timeout", str(max(1, int(context.timeout))), "-retries", "0",
        "-allow", ",".join(context.scope.include_ips),
    ]
    result = run_tool("httpx", args, context.timeout * 2, "".join(f"{host}\n" for host in hosts))
    if result.error:
        return [], result.error
    services: list[Service] = []
    parse_errors = 0
    for line in result.output.splitlines():
        try:
            item = json.loads(line)
            url = str(item.get("url", ""))
            parsed = urlsplit(url)
            host = parsed.hostname or ""
            if parsed.scheme not in ("http", "https") or parsed.username or parsed.password or not context.scope.allows(host):
                context.logger.warning("Rejected out-of-scope httpx result: %s", url)
                continue
            services.append(Service(
                url=url,
                host=host,
                status_code=item.get("status_code"),
                title=str(item.get("title", "")),
                content_type=str(item.get("content_type", "")),
                server=str(item.get("webserver", "")),
            ))
        except (json.JSONDecodeError, AttributeError, TypeError, ValueError):
            parse_errors += 1
    return services, f"httpx returned {parse_errors} unparseable result line(s)" if parse_errors else None


def run(context: RunContext) -> ModuleResult:
    records = context.data.get("dns_records", [])
    records_by_host = {
        str(record["host"]): record
        for record in records
        if record.get("safe_for_network_modules") and context.scope.allows(str(record["host"]))
    }
    hosts = sorted(records_by_host)
    services: list[Service] = []
    error: str | None = None
    if hosts:
        # External httpx performs its own DNS lookups, so use it only when each
        # current DNS address has also been explicitly authorized in the scope.
        explicitly_allowed = all(
            addresses and all(context.scope.allows_ip(address) for address in addresses)
            for addresses in (record.get("public_addresses", []) for record in records_by_host.values())
        )
        if explicitly_allowed and tool_available("httpx"):
            candidate, error = _httpx_probe(context, hosts)
            services = candidate
        if not services:
            context.logger.info("Using the built-in HTTP probe with DNS-pinned connections%s", f" ({error})" if error else "")
            with concurrent.futures.ThreadPoolExecutor(max_workers=context.workers) as executor:
                services = list(executor.map(
                    lambda host: _native_probe(host, list(records_by_host[host]["public_addresses"]), context.timeout),
                    hosts,
                ))

    services = [service for service in services if context.scope.allows(service.host)]
    live = [service for service in services if service.status_code is not None]
    context.data["services"] = [asdict(service) for service in services]
    context.data["live_urls"] = sorted({service.url for service in live})
    context.storage.write_lines("subdomains/alive.txt", context.data["live_urls"])
    context.storage.write_json("http/services.json", context.data["services"])
    context.logger.info("HTTP probing found %d live service(s)", len(live))
    failed = sum(service.status_code is None for service in services)
    state = "partial" if failed or error else "success"
    return ModuleResult("http", state, "HTTP probing completed with failures" if state == "partial" else "HTTP probing completed", {"live": len(live), "failed": failed, "probe_warning": error})
