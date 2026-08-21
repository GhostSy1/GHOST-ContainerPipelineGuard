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
