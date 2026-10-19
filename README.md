# k-recon

**A Modular Reconnaissance Framework for Authorized Bug Bounty Hunting**

`k-recon` is a Python-based reconnaissance framework designed to organize and streamline asset discovery for authorized bug bounty programs and security assessments.

## Features

- **Scope Enforcement** — Keep reconnaissance activities within defined targets.
- **Asset Discovery** — Discover and organize target assets.
- **DNS Resolution** — Resolve and deduplicate discovered domains.
- **HTTP Probing** — Identify live web services.
- **URL Collection** — Collect URLs for further analysis.
- **Tool Integration** — Integrate with external reconnaissance tools.
- **Structured Logging** — Track execution and errors.
- **Reporting** — Export results in machine-readable formats.

> Features are being developed incrementally. Check the project status before relying on any feature.

## Project Goals

- Build a modular and maintainable reconnaissance workflow.
- Enforce target scope before executing reconnaissance modules.
- Reduce duplicate results and improve data organization.
- Make it easy to extend the framework with new tools and modules.
- Support repeatable and structured security assessments.

## Installation

Clone the repository:

```bash
git clone https://github.com/KhitMinnyo/k-recon.git
cd k-recon
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the project once packaging configuration is available:

```bash
pip install -e .
```

## Usage

The command-line interface and configuration format are under development.

The intended workflow is:

1. Define the authorized target scope.
2. Run asset discovery.
3. Resolve and validate discovered assets.
4. Probe live services and collect URLs.
5. Review and export reconnaissance results.

Refer to the latest project documentation for supported commands and configuration options.

## Roadmap

- [ ] Modular Python core
- [ ] Scope allowlist and exclusion rules
- [ ] Subdomain discovery integrations
- [ ] DNS resolution and deduplication
- [ ] HTTP probing
- [ ] Historical URL collection
- [ ] JSON reporting
- [ ] Optional port scanning integration
- [ ] Automated tests and CI
- [ ] HTML reports

## Security & Responsible Use

`k-recon` is intended for authorized security testing, bug bounty programs, and systems you have explicit permission to assess.

Always verify the program's scope and rules before running reconnaissance. Scope enforcement is a core design goal, but users should independently validate target authorization and tool behavior.

## Contributing

Contributions, bug reports, feature requests, and improvements are welcome.

Please open an issue to discuss significant changes before submitting a pull request.

## License

The project license will be specified in the repository.

---

**Author:** [Khit Minnyo](https://github.com/KhitMinnyo)

**Project:** [github.com/KhitMinnyo/k-recon](https://github.com/KhitMinnyo/k-recon)
