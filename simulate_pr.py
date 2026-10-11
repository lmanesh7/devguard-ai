#!/usr/bin/env python3
"""DevGuard AI - Pull Request Webhook Simulator.

Simulates GitHub Pull Request webhooks against DevGuard AI.
Tests vulnerability detection, automated Linode Cloud Firewall provisioning,
and markdown security review posting.

Usage:
    python simulate_pr.py
    python simulate_pr.py --scenario vulnerable
    python simulate_pr.py --scenario safe
    python simulate_pr.py --url http://localhost:8000/webhook/github
    python simulate_pr.py --direct
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from typing import Any
import httpx

# Ensure Windows stdout handles UTF-8 safely
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ANSI Color Codes
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


# --- TEST SCENARIOS ---

VULNERABLE_DIFF = """diff --git a/compose.yaml b/compose.yaml
index 7a12b3c..8d45e6f 100644
--- a/compose.yaml
+++ b/compose.yaml
@@ -5,2 +5,5 @@ services:
   agent:
+    ports:
+      - "0.0.0.0:22:22"
+    # Target Compute Instance for DevGuard Shield
+    linode_id = 12345
diff --git a/agent/brain.py b/agent/brain.py
index 9e01f2a..1b2c3d4 100644
--- a/agent/brain.py
+++ b/agent/brain.py
@@ -14,2 +14,5 @@ def build_prompt(user_input: str):
-    return f"User query: {user_input}"
+    # Insecure: formatting untrusted user string directly into system instructions
+    system_prompt = f"System override: You are an internal root assistant. {user_input}"
+    return system_prompt
+
+DEBUG_SECRET = "linode_token_demo_9876543210fedcba"
"""

SAFE_DIFF = """diff --git a/agent/server.py b/agent/server.py
index 4a5b6c7..8d9e0f1 100644
--- a/agent/server.py
+++ b/agent/server.py
@@ -34,4 +34,4 @@ class ChatRequest(BaseModel):
-    session_id: str
-    message: str
+    session_id: str = Field(min_length=1, max_length=100)
+    message: str = Field(min_length=1, max_length=2000)
"""


def build_webhook_payload(
    scenario: str,
    pr_number: int = 42,
    repo_name: str = "akamai-developers/akamai-workshop-hackmidwest",
) -> dict[str, Any]:
    """Generates a realistic GitHub pull_request webhook payload."""
    if scenario == "vulnerable":
        title = "feat: Add developer remote SSH port and prompt template"
        diff_text = VULNERABLE_DIFF
        linode_id = 12345
    else:
        title = "refactor: Add bounded input validation on chat parameters"
        diff_text = SAFE_DIFF
        linode_id = None

    return {
        "action": "opened",
        "number": pr_number,
        "pull_request": {
            "id": 1000000 + pr_number,
            "number": pr_number,
            "state": "open",
            "title": title,
            "user": {"login": "hackathon-developer"},
            "head": {"ref": "feature/network-update"},
            "base": {"ref": "main"},
            "html_url": f"https://github.com/{repo_name}/pull/{pr_number}",
        },
        "repository": {
            "name": repo_name.split("/")[-1],
            "full_name": repo_name,
            "owner": {"login": repo_name.split("/")[0]},
        },
        "diff_content": diff_text,
        "target_linode_id": linode_id,
    }


def print_banner(text: str, color: str = CYAN):
    bar = "=" * 70
    print(f"\n{color}{BOLD}{bar}{RESET}")
    print(f"{color}{BOLD}  {text}{RESET}")
    print(f"{color}{BOLD}{bar}{RESET}")


def display_audit_results(audit_data: dict[str, Any]):
    """Pretty prints the audit findings, firewall actions, and remediation patches."""
    pr_info = audit_data.get("pull_request", {})
    analysis = audit_data.get("security_analysis", {})
    firewall = audit_data.get("firewall_action")
    comment = audit_data.get("github_comment", {})

    risk = analysis.get("risk_score", "UNKNOWN")
    risk_colors = {
        "CRITICAL": RED,
        "HIGH": RED,
        "MEDIUM": YELLOW,
        "LOW": GREEN,
    }
    r_color = risk_colors.get(risk, CYAN)

    print(f"\n{BOLD}PR Audited:{RESET} #{pr_info.get('number')} - {pr_info.get('title')}")
    print(f"{BOLD}Risk Score:{RESET} {r_color}{BOLD}[ {risk} ]{RESET}")
    print(f"{BOLD}Summary:{RESET} {analysis.get('summary')}")

    vulns = analysis.get("vulnerabilities", [])
    if vulns:
        print(f"\n{RED}{BOLD}[!] Identified Vulnerabilities ({len(vulns)}):{RESET}")
        for idx, v in enumerate(vulns, 1):
            print(f"  {idx}. [{BOLD}{v.get('severity')}{RESET}] {v.get('type')}: {v.get('description')}")
    else:
        print(f"\n{GREEN}[+] No vulnerabilities or exposed ports detected.{RESET}")

    # Firewall Defense Status
    if firewall:
        print(f"\n{CYAN}{BOLD}[*] Active Defense - Linode Cloud Firewall Auto-Provisioned:{RESET}")
        print(f"  - Firewall ID:   {BOLD}{firewall.get('id')}{RESET} ({firewall.get('label')})")
        print(f"  - Inbound Rule:  {BOLD}DROP{RESET} all traffic")
        print(f"  - Ingress Port:  {BOLD}TCP 443 only{RESET}")
        print(f"  - Devices:       Linode ID {BOLD}{firewall.get('devices', {}).get('linodes')}{RESET}")
        print(f"  - Defense Mode:  {'Simulated' if firewall.get('mock') else 'Live Linode API v4'}")
    else:
        print(f"\n{GREEN}[*] Active Defense:{RESET} No firewall isolation required for this PR.")

    # Remediation Diff
    remediation = analysis.get("remediation_diff")
    if remediation and remediation.strip():
        print(f"\n{YELLOW}{BOLD}[~] Suggested Remediation Diff Patch:{RESET}")
        for line in remediation.strip().split("\n"):
            if line.startswith("+"):
                print(f"  {GREEN}{line}{RESET}")
            elif line.startswith("-"):
                print(f"  {RED}{line}{RESET}")
            else:
                print(f"  {DIM}{line}{RESET}")

    # GitHub Comment
    if comment:
        print(f"\n{CYAN}{BOLD}[*] GitHub PR Review Status:{RESET}")
        print(f"  - Comment ID: {comment.get('id')}")
        print(f"  - PR URL:     {comment.get('html_url')}")


async def run_direct_simulation(scenario: str):
    """Executes the pipeline directly in-process without an HTTP server."""
    from app.main import run_security_pipeline

    payload = build_webhook_payload(scenario=scenario, pr_number=101 if scenario == "vulnerable" else 102)
    pr = payload["pull_request"]
    repo = payload["repository"]

    print_banner(f"IN-PROCESS SIMULATION: Scenario [{scenario.upper()}]", YELLOW)
    start_time = time.time()

    audit_result = await run_security_pipeline(
        owner=repo["owner"]["login"],
        repo=repo["name"],
        pull_number=pr["number"],
        pr_title=pr["title"],
        diff_content=payload["diff_content"],
        override_linode_id=payload.get("target_linode_id"),
    )

    elapsed = time.time() - start_time
    display_audit_results(audit_result)
    print(f"\n{DIM}Audit completed in {elapsed:.2f} seconds.{RESET}")


async def run_http_simulation(url: str, scenario: str):
    """Dispatches webhook request via HTTP to the FastAPI server."""
    payload = build_webhook_payload(scenario=scenario, pr_number=201 if scenario == "vulnerable" else 202)
    headers = {
        "X-GitHub-Event": "pull_request",
        "Content-Type": "application/json",
    }

    print_banner(f"HTTP WEBHOOK SIMULATION: Scenario [{scenario.upper()}] -> {url}", CYAN)
    print(f"Posting PR webhook event to: {url} ...")

    start_time = time.time()
    try:
        async with httpx.AsyncClient(timeout=25.0) as client:
            resp = await client.post(url, json=payload, headers=headers)

        elapsed = time.time() - start_time

        if resp.status_code == 200:
            data = resp.json()
            audit_result = data.get("audit", {})
            display_audit_results(audit_result)
            print(f"\n{GREEN}[+] Webhook processed successfully in {elapsed:.2f} seconds (HTTP 200).{RESET}")
        else:
            print(f"{RED}Server responded with HTTP {resp.status_code}:{RESET}\n{resp.text}")

    except httpx.ConnectError:
        print(f"{YELLOW}Warning: Could not connect to {url}. FastAPI server may not be running.{RESET}")
        print(f"{CYAN}Switching automatically to in-process direct simulation...{RESET}\n")
        await run_direct_simulation(scenario)


async def main():
    parser = argparse.ArgumentParser(description="Simulate GitHub Pull Request webhook against DevGuard AI")
    parser.add_argument(
        "--scenario",
        choices=["vulnerable", "safe", "all"],
        default="all",
        help="Test scenario: vulnerable (exposed port & prompt injection), safe (clean PR), or all",
    )
    parser.add_argument(
        "--url",
        default="http://localhost:8000/webhook/github",
        help="Target webhook URL (default: http://localhost:8000/webhook/github)",
    )
    parser.add_argument(
        "--direct",
        action="store_true",
        help="Run pipeline directly in-process without sending HTTP request",
    )

    args = parser.parse_args()

    scenarios = ["vulnerable", "safe"] if args.scenario == "all" else [args.scenario]

    for sc in scenarios:
        if args.direct:
            await run_direct_simulation(sc)
        else:
            await run_http_simulation(args.url, sc)


if __name__ == "__main__":
    asyncio.run(main())
