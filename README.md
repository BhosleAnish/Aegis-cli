# Aegis CLI

Automation-first **VAPT / infrastructure / SAST** scanner for **authorized**
security engagements — command line only. One operator, one box, no server, no
database, no web UI. Point it at a target you are allowed to test and it writes
a findings report to disk.

> This is the standalone CLI edition of the Aegis engine. The multi-tenant
> platform (web portal, remote agent fleet, dashboard) lives in a separate
> project; everything here runs locally from your terminal.

---

## Install

Requires **Python 3.10+**. Recommended: [`pipx`](https://pipx.pypa.io/) so the
`aegis` command lands on your PATH in its own isolated environment.

```bash
pipx install git+https://github.com/<you>/aegis-cli.git
```

With PDF report export (`--pdf`):

```bash
pipx install "aegis-cli[pdf] @ git+https://github.com/<you>/aegis-cli.git"
```

Or plain `pip` into a virtualenv:

```bash
pip install git+https://github.com/<you>/aegis-cli.git
```

### From a clone

```bash
git clone https://github.com/<you>/aegis-cli.git
cd aegis-cli
pip install -e .          # adds the `aegis` command
# or, without installing:
python -m aegis --help
```

### External tools

The engine is stdlib + PyYAML + defusedxml. Active scanning **shells out** to
standard OSS tools (`nmap`, `httpx`, `nuclei`, `katana`, `gau`, `ffuf`,
`dalfox`, `bandit`, `semgrep`, `gitleaks`, …). Install whichever you need and
put them on your PATH — each adapter degrades gracefully if its binary is
missing. Check what's available:

```bash
aegis doctor
```

---

## Authorization gate

Every scanning command requires two YAML files and **refuses to run without
them**. This is deliberate: Aegis only tests what you can prove you are
permitted to test.

- **`--scope`** — what is in bounds (include / exclude / ports). See
  [`examples/scope.example.yaml`](examples/scope.example.yaml).
- **`--auth`** — proof of permission (client, named approver, validity window,
  rules of engagement). Refused if missing, unsigned, undated, or expired. See
  [`examples/authorization.example.yaml`](examples/authorization.example.yaml).

Copy both, fill them in from your signed SoW / RoE, then validate before you
scan anything:

```bash
aegis check --scope scope.yaml --auth authorization.yaml
```

---

## Usage

```bash
aegis <command> --scope scope.yaml --auth authorization.yaml [options]
```

| Command | What it does |
|---|---|
| `aegis scan`   | Full web/network VAPT pipeline (discovery → probe → vuln) |
| `aegis infra`  | Infrastructure analysis from host inventory (`--agent-dir` or `--infra-json`) |
| `aegis sast`   | Static code review of a source tree (bandit / semgrep / gitleaks) |
| `aegis check`  | Validate scope + authorization without scanning |
| `aegis doctor` | Report which external tools are installed |

Reports are written to `runs/` by default (`--out` to change). Add `--pdf` to
also export a PDF (needs the `[pdf]` extra).

### Examples

```bash
# Safe (passive, non-destructive) web VAPT
aegis scan --scope scope.yaml --auth authorization.yaml

# Match detected web tech against known CVEs (NVD + OSV)
aegis scan --scope scope.yaml --auth authorization.yaml --web-cve

# More intrusive active testing (only within your RoE)
aegis scan --scope scope.yaml --auth authorization.yaml --intensity aggressive

# Authenticated / grey-box scan
aegis scan --scope scope.yaml --auth authorization.yaml \
  --mode greybox --cookie "session=..." --auth-header "Authorization: Bearer ..."

# Static code review of a repo
aegis sast --path ./my-app --auth authorization.yaml

# Infrastructure review from a pre-collected inventory JSON, with CVE matching
aegis infra --scope scope.yaml --auth authorization.yaml --infra-json inv.json --cve
```

Run `aegis <command> --help` for the full option set.

---

## Development

```bash
pip install -e ".[dev]"
pytest
```

---

## Legal

Use Aegis **only** against systems you own or are explicitly authorized to test.
Unauthorized scanning may be illegal. The authorization gate is a safeguard, not
a substitute for a signed agreement.

MIT licensed.
