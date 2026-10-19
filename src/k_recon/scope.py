"""Strict DNS name normalization and scope enforcement."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalize_domain(value: str) -> str:
    """Return a normalized DNS name; reject IP literals and URL paths."""
    raw = value.strip()
    if not raw:
        raise ValueError("domain cannot be empty")
    if raw.startswith("*."):
        raw = raw[2:]

    if "://" in raw:
        parsed = urlsplit(raw)
        if parsed.username or parsed.password or parsed.port:
            raise ValueError("target URLs must not contain credentials or ports")
        if parsed.netloc.endswith(":"):
            raise ValueError("target URLs must not contain an empty port")
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise ValueError("expected a domain name without a path, query, or fragment")
        hostname = parsed.hostname or ""
    else:
        if any(char in raw for char in "/\\@:#?%"):
            raise ValueError(f"invalid domain name: {value!r}")
        hostname = raw

    try:
        domain = hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError(f"invalid internationalized domain name: {value!r}") from exc
    if not domain or len(domain) > 253 or "." not in domain:
        raise ValueError(f"expected a fully qualified domain name, got {value!r}")
    if any(not _LABEL.fullmatch(label) for label in domain.split(".")):
        raise ValueError(f"invalid domain name: {value!r}")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return domain
    raise ValueError("IP addresses must be explicitly handled as IP scope, not domain scope")


@dataclass(frozen=True)
class Scope:
    include: tuple[str, ...]
    exclude: tuple[str, ...] = ()
    include_ips: tuple[str, ...] = ()

    @classmethod
    def create(
        cls,
        include: list[str] | tuple[str, ...],
        exclude: list[str] | tuple[str, ...] = (),
        include_ips: list[str] | tuple[str, ...] = (),
    ) -> "Scope":
        roots = tuple(sorted({normalize_domain(item) for item in include}))
        exclusions = tuple(sorted({normalize_domain(item) for item in exclude}))
        if not roots:
            raise ValueError("scope must contain at least one in-scope domain")
        for domain in exclusions:
            if not any(domain == root or domain.endswith(f".{root}") for root in roots):
                raise ValueError(f"excluded domain {domain!r} is outside the configured scope")
        networks: set[str] = set()
        for value in include_ips:
            try:
                networks.add(str(ipaddress.ip_network(value, strict=False)))
            except ValueError as exc:
                raise ValueError(f"invalid IP address or network in scope: {value!r}") from exc
        return cls(roots, exclusions, tuple(sorted(networks)))

    def allows(self, value: str) -> bool:
        try:
            domain = normalize_domain(value)
        except ValueError:
            return False
        included = any(domain == root or domain.endswith(f".{root}") for root in self.include)
        excluded = any(domain == item or domain.endswith(f".{item}") for item in self.exclude)
        return included and not excluded

    def allows_url(self, value: str) -> bool:
        try:
            parsed = urlsplit(value)
            if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
                return False
            if parsed.username or parsed.password or parsed.netloc.endswith(":"):
                return False
            if parsed.port == 0:
                return False
        except ValueError:
            return False
        return self.allows(parsed.hostname)

    def filter(self, values: list[str] | set[str]) -> tuple[list[str], list[str]]:
        accepted: set[str] = set()
        rejected: list[str] = []
        for value in values:
            try:
                domain = normalize_domain(value)
            except ValueError:
                rejected.append(value)
                continue
            if self.allows(domain):
                accepted.add(domain)
            else:
                rejected.append(value)
        return sorted(accepted), sorted(rejected)

    def allows_ip(self, value: str) -> bool:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False
        return address.is_global and any(address in ipaddress.ip_network(network) for network in self.include_ips)
