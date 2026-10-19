"""Concurrent A/AAAA resolution with public-address eligibility checks."""

from __future__ import annotations

import concurrent.futures
import ipaddress

import dns.exception
import dns.resolver

from k_recon.models import ModuleResult, RunContext


def _resolve(host: str, timeout: float) -> dict[str, object]:
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2
    addresses: set[str] = set()
    errors: list[str] = []
    for record_type in ("A", "AAAA"):
        try:
            answer = resolver.resolve(host, record_type, raise_on_no_answer=False)
            if answer.rrset:
                addresses.update(item.address for item in answer)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
            errors.append(f"{record_type}: {type(exc).__name__}")
        except dns.exception.DNSException as exc:
            errors.append(f"{record_type}: {type(exc).__name__}: {exc}")

    ordered = sorted(addresses)
    public = [address for address in ordered if ipaddress.ip_address(address).is_global]
    return {
        "host": host,
        "addresses": ordered,
        "public_addresses": public,
        "safe_for_network_modules": bool(ordered) and len(public) == len(ordered),
        "errors": errors,
    }


def run(context: RunContext) -> ModuleResult:
    hosts = context.data.get("hosts", [context.target])
    hosts = [host for host in hosts if context.scope.allows(host)]
    records: list[dict[str, object]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=context.workers) as executor:
        futures = {executor.submit(_resolve, host, context.timeout): host for host in hosts}
        for future in concurrent.futures.as_completed(futures):
            host = futures[future]
            try:
                records.append(future.result())
            except Exception as exc:  # Keep one resolver failure from aborting the run.
                context.logger.exception("DNS resolution failed for %s", host)
                records.append({"host": host, "addresses": [], "public_addresses": [], "safe_for_network_modules": False, "errors": [str(exc)]})
    records.sort(key=lambda record: str(record["host"]))
    safe_hosts = [str(record["host"]) for record in records if record["safe_for_network_modules"]]
    context.data["dns_records"] = records
    context.data["safe_hosts"] = safe_hosts
    context.storage.write_json("dns/records.json", records)
    context.storage.write_lines("subdomains/resolved.txt", safe_hosts)
    rejected = len(records) - len(safe_hosts)
    context.logger.info("DNS found %d safe host(s); %d unresolved or unsafe host(s)", len(safe_hosts), rejected)
    state = "partial" if rejected else "success"
    return ModuleResult("dns", state, "Some hosts did not resolve safely" if rejected else "DNS resolution completed", {"resolved": len(safe_hosts), "rejected": rejected})
