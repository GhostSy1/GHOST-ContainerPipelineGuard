# GHOST-ContainerPipelineGuard

Enterprise Dockerfile & CI/CD Security Auditor developed by Abdulaziz (Ghost-SY1).

## Overview & Purpose
`GHOST-ContainerPipelineGuard` inspects container build definitions, Dockerfiles, and CI/CD pipelines for insecure practices (root execution, remote ADD, hardcoded secrets) without simulation.

## Installation & Setup
```bash
git clone https://github.com/GhostSy1/GHOST-ContainerPipelineGuard.git
cd GHOST-ContainerPipelineGuard
python3 -m pip install -r requirements.txt
```

## Usage
```bash
python3 main.py --dockerfile Dockerfile --json report.json
```

## Engineering and release baseline

This repository is maintained as part of the Ghost-SY1 security engineering portfolio. The project is intended for authorized assessment, analysis, or defensive engineering, according to the concrete behavior implemented in the source tree. Results must be derived from operator-supplied inputs and should be reviewed against the documented limitations before they are used in a decision.

### Repository map

| Path | Purpose |
|---|---|
| `README.md` | Installation, usage, scope, and limitations |
| `docs/` | Detailed operational and architectural documentation |
| `tests/` | Reproducible checks for implemented behavior |
| `.github/workflows/` | Automated quality and release checks |
| `SECURITY.md` | Vulnerability reporting and release hygiene |
| `CONTRIBUTING.md` | Contribution and review requirements |

### Verification

Run the repository-specific command documented above, then run the checks in `.github/workflows/quality.yml` locally where the required runtime is available. Do not interpret a passing syntax check as proof that every deployment or security decision is correct.

### Responsible use

Use only with explicit authorization. Do not commit credentials, private keys, customer data, or raw engagement artifacts. The repository does not provide a guarantee that an observation is a vulnerability; analysts must preserve evidence and validate conclusions independently.

## Domain extension

This repository includes `tools/ghost_extension.py`, a standalone local-input analyzer for the repository domain. It hashes every inspected file, records the source location for each observable indicator, and emits JSON with optional CSV and SARIF output. It does not execute supplied content, make network requests, or invoke external security utilities.

```bash
python3 tools/ghost_extension.py --input ./evidence --output report.json --sarif report.sarif
```

The extension is an evidence triage aid. A marker is not a confirmed vulnerability; validate it against the authorized environment and the repository's documented limitations.

