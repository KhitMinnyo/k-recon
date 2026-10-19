"""Command-line interface for k-recon."""

from __future__ import annotations

import argparse
import math
import sys
from pathlib import Path

from k_recon import __version__
from k_recon.config import load_scope
from k_recon.modules.base import tool_available
from k_recon.runner import MODULES, ScanInterrupted, run_scan

TOOLS = {
    "subfinder": "Passive subdomain enumeration",
    "assetfinder": "Passive subdomain enumeration",
    "amass": "Passive subdomain enumeration",
    "httpx": "HTTP service probing (built-in fallback available)",
    "gowitness": "Website screenshots",
    "waybackurls": "Historical URL collection",
    "gau": "Historical URL collection",
    "nmap": "Explicitly authorized port and service scanning",
}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="k-recon", description="Modular, scope-aware reconnaissance for authorized assessments.")
    parser.add_argument("--version", action="version", version=f"k-recon {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="run selected reconnaissance modules")
    scan.add_argument("--domain", required=True, help="target domain to assess")
    scan.add_argument("--scope", type=Path, help="YAML scope allowlist; without it, the target domain is the scope root")
    scan.add_argument("--modules", default="discovery,dns,http,urls", help=f"comma-separated modules: {','.join(MODULES)}")
    scan.add_argument("--output", type=Path, default=Path("results"), help="output directory (default: results)")
    scan.add_argument("--timeout", type=float, default=8.0, help="per-tool call, DNS query, and HTTP connection timeout in seconds")
    scan.add_argument("--workers", type=int, default=10, help="maximum concurrent DNS/HTTP requests (1-100)")
    scan.add_argument("--enable-nmap", action="store_true", help="explicitly enable all-port Nmap service scanning")
    scan.add_argument("--authorized", action="store_true", help="confirm that you have permission to assess this target")
    scan.add_argument("--verbose", action="store_true", help="show debug-level run settings")

    tools = commands.add_parser("tools", help="show optional external tool availability")
    tools.add_argument("--json", action="store_true", help="print machine-readable tool status")
    return parser


def _show_tools(as_json: bool) -> int:
    import json

    statuses = [{"name": name, "purpose": purpose, "available": tool_available(name)} for name, purpose in TOOLS.items()]
    if as_json:
        print(json.dumps(statuses, indent=2))
    else:
        for item in statuses:
            status = "available" if item["available"] else "not installed"
            print(f"{item['name']:<14} {status:<14} {item['purpose']}")
        print("DNS uses dnspython; HTTP probing has a standard-library fallback.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command == "tools":
        return _show_tools(args.json)

    if not args.authorized:
        parser.error("scan requires --authorized; only assess systems you have permission to test")
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout must be a finite number greater than zero")
    if not 1 <= args.workers <= 100:
        parser.error("--workers must be between 1 and 100")

    selected = [value.strip() for value in args.modules.split(",") if value.strip()]
    if not selected or len(selected) != len(set(selected)):
        parser.error("--modules must be a non-empty comma-separated list without duplicates")
    if "ports" in selected and not args.enable_nmap:
        parser.error("the ports module requires --enable-nmap")
    if args.enable_nmap and "ports" not in selected:
        selected.append("ports")

    try:
        scope = load_scope(args.scope, args.domain)
        run_dir, results = run_scan(
            args.domain,
            scope,
            args.output,
            selected,
            args.timeout,
            args.workers,
            args.enable_nmap,
            args.verbose,
        )
    except ScanInterrupted as exc:
        print(f"k-recon: interrupted; partial artifacts preserved at {exc.run_dir}", file=sys.stderr)
        return 130
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"k-recon: error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("k-recon: interrupted before a run could be finalized", file=sys.stderr)
        return 130

    failed = sum(result.state == "failed" for result in results)
    partial = sum(result.state == "partial" for result in results)
    print(f"Run directory: {run_dir}")
    print(f"Module summary: {len(results) - failed - partial} succeeded, {partial} partial, {failed} failed")
    return 1 if failed else 0
