#!/usr/bin/env python3
import os
import sys
import json
import argparse
import re

os.environ.pop('SSLKEYLOGFILE', None)

BANNER = r"""
╭────────────────────────────────────────────────────────────────────────────────────────╮
│                                                                                        │
│  ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗     ██╗███╗   ██╗████████╗███████╗██╗      │
│ ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝     ██║████╗  ██║╚══██╔══╝██╔════╝██║      │
│ ██║  ███╗███████║██║   ██║███████╗   ██║        ██║██╔██╗ ██║   ██║   █████╗  ██║      │
│ ██║   ██║██╔══██║██║   ██║╚════██║   ██║        ██║██║╚██╗██║   ██║   ██╔══╝  ██║      │
│ ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ██╗  ██║██║ ╚████║   ██║   ███████╗███████╗ │
│  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝ │
│      GHOST-ContainerPipelineGuard: Enterprise Dockerfile & CI/CD Security Auditor      │
│                                                                                        │
╰────────────────────────────────────────────────────────────────────────────────────────╯
"""

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

SECRET_PATTERNS = [
    re.compile(r'api[_-]?key\s*[:=]\s*[\'"][0-9a-zA-Z-_]{16,}[\'"]', re.I),
    re.compile(r'password\s*[:=]\s*[\'"].+?[\'"]', re.I),
    re.compile(r'bearer\s+[0-9a-zA-Z\-\._~\+\/]+=*', re.I),
]

def scan_dockerfile(path: str) -> list:
    findings = []
    if not os.path.exists(path):
        return findings
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
    
    for idx, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.upper().startswith("USER ROOT") or stripped.upper() == "USER 0":
            findings.append({
                "line": idx,
                "severity": "HIGH",
                "issue": "Container running as root user (USER root/0)."
            })
        if "ADD " in stripped and ("http://" in stripped or "https://" in stripped):
            findings.append({
                "line": idx,
                "severity": "MEDIUM",
                "issue": "Using ADD with remote URL instead of COPY/curl."
            })
        for pattern in SECRET_PATTERNS:
            if pattern.search(line):
                findings.append({
                    "line": idx,
                    "severity": "CRITICAL",
                    "issue": "Potential hardcoded secret or API key in Dockerfile."
                })
    return findings

def main():
    clear_screen()
    print(BANNER)
    
    parser = argparse.ArgumentParser(description="GHOST-ContainerPipelineGuard: Docker & CI/CD Security")
    parser.add_argument("--dockerfile", help="Path to Dockerfile to inspect", default="Dockerfile")
    parser.add_argument("--json", help="Path to save report", default="pipeline_guard_report.json")
    args = parser.parse_args()

    print(f"[*] Inspecting container pipeline target: {args.dockerfile}")
    
    findings = scan_dockerfile(args.dockerfile)
    
    report = {
        "target": args.dockerfile,
        "total_findings": len(findings),
        "findings": findings
    }

    with open(args.json, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    print(f"[+] Pipeline security audit complete. Report saved to: {args.json}")

if __name__ == "__main__":
    main()
