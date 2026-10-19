# k-recon

**A Modular Reconnaissance Framework for Authorized Security Testing**

`k-recon` is a Python 3.11+ command-line framework for organizing authorized reconnaissance. It enforces a domain allowlist before passing targets to external tools and stores every execution in an isolated run directory.

## Features

- Scope allowlists, excluded domains, DNS label-boundary checks, and explicit IP authorization for Nmap.
- Independent Subfinder, Assetfinder, and Amass discovery adapters with per-provider results.
- Concurrent DNS resolution and public-address checks before HTTP or port-scan modules.
- DNS-pinned HTTP probing through the standard library, with ProjectDiscovery httpx available when all current addresses are explicitly authorized.
- Optional GoWitness screenshots and historical URL collection through Waybackurls and gau.
- Nmap port and service scans only when explicitly enabled and IPs are separately allowlisted.
- Per-run logs, atomic framework-managed text/JSON writes, machine-readable reports, and mocked tests.

External reconnaissance tools are optional. Missing tools are reported in the run results; unrelated modules continue when their dependencies are available. DNS resolution requires `dnspython`; YAML configuration uses PyYAML.

## Installation

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install .
```

Install only the external tools needed for the modules you plan to run. `k-recon tools` reports which supported tools are available. Nmap must be installed separately and is never run unless explicitly enabled.

## Scope Configuration

Copy `config/scope.example.yaml` to `config/scope.yaml` and replace the example values. The local scope file is ignored by Git.

```yaml
scope:
  include:
    - example.com
  exclude:
    - private.example.com
  include_ips: []
```

The target passed to `--domain` must match an included domain. Subdomains match only on DNS label boundaries: `api.example.com` is in scope, while `notexample.com` is not. `include_ips` accepts explicit IP addresses or CIDRs for Nmap; DNS results alone do not authorize an IP scan. Non-global DNS addresses are not sent to HTTP or Nmap modules.

Without `--scope`, the supplied domain is the only scope root and no IP is authorized for Nmap.

## Usage

Show the CLI and optional tool status:

```bash
k-recon --help
k-recon tools
k-recon tools --json
```

Run the standard passive discovery, DNS, HTTP, and historical URL workflow:

```bash
k-recon scan --domain example.com --scope config/scope.yaml --authorized
```

Choose modules explicitly. Dependencies are included automatically; for example, selecting `http` also schedules discovery and DNS:

```bash
k-recon scan --domain example.com --scope config/scope.yaml \
  --modules discovery,dns,http --authorized --timeout 10 --workers 8
```

Screenshots are opt-in through module selection:

```bash
k-recon scan --domain example.com --scope config/scope.yaml \
  --modules discovery,dns,http,screenshots --authorized
```

Nmap requires both an explicit IP/CIDR in `scope.include_ips` and the opt-in flag:

```bash
k-recon scan --domain example.com --scope config/scope.yaml \
  --modules discovery,dns --enable-nmap --authorized
```

Nmap scans all TCP ports with service detection and can generate substantial traffic. Confirm program rules and authorization before enabling it. `--authorized` is a confirmation, not proof of permission.

## Run Artifacts

Each scan creates a unique directory and does not overwrite earlier runs:

```text
results/example.com/runs/<run-id>/
├── scope.txt
├── subdomains/
│   ├── subfinder.txt
│   ├── assetfinder.txt
│   ├── amass.txt
│   ├── all.txt
│   ├── resolved.txt
│   └── alive.txt
├── dns/records.json
├── http/services.json
├── urls/                 # included by the default module set
├── logs/recon.log
└── report.json
```

`screenshots/` appears only when the `screenshots` module is selected. `scans/` appears only when `--enable-nmap` is used. DNS and HTTP artifacts are present when those modules run; dependencies are added automatically for selected downstream modules.

The report records module state (`success`, `partial`, `failed`, or `skipped`), provider errors, the HTTP backend used, and run timestamps. Discovery and URL modules record missing providers individually; they are partial if no provider completes or any selected provider fails. Missing GoWitness produces a partial screenshot result. Unavailable httpx is reported as the built-in DNS-pinned fallback in the HTTP result. A requested Nmap run fails if Nmap cannot start. Framework-managed text and JSON files are written atomically; files produced directly by external tools are not.

## Safety Boundaries

- Discovery output is normalized and scope-filtered before storage or downstream use.
- HTTP modules receive only validated domains with public DNS answers. The built-in probe pins connections to the checked addresses and does not follow redirects. ProjectDiscovery httpx is used only when each current address is explicitly allowlisted; redirect following is not enabled.
- Screenshot tools receive only validated live URLs and are an explicit module choice. Browser-driven pages can initiate additional requests; use screenshots only where program rules permit them.
- Nmap is never selected by default. It scans only public resolved addresses explicitly allowed by `scope.include_ips`.
- The framework does not perform exploitation, brute force, or destructive checks.

## Development

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

External commands are mocked in the unit suite. Tests do not require installed reconnaissance tools or access to target networks.

## License

This project is licensed under the MIT License. See `LICENSE`.
