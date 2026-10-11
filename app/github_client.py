"""DevGuard AI - GitHub REST API Client.

Asynchronous client for retrieving Pull Request diffs and publishing
automated markdown security audit reviews and firewall defense reports.
"""
from __future__ import annotations

import logging
from typing import Any
import httpx

from app.config import settings

logger = logging.getLogger("devguard.github")

GITHUB_API_BASE = "https://api.github.com"


def format_security_review_comment(analysis: dict[str, Any], firewall_result: dict[str, Any] | None = None) -> str:
    """Formats an automated GitHub markdown review comment from analysis and active defense results."""
    risk_score = analysis.get("risk_score", "UNKNOWN")
    summary = analysis.get("summary", "No summary provided.")
    vulnerabilities = analysis.get("vulnerabilities", [])
    remediation_diff = analysis.get("remediation_diff", "")
    requires_firewall = analysis.get("requires_firewall_action", False)

    # Risk badge
    risk_badges = {
        "CRITICAL": "🚨 **CRITICAL RISK**",
        "HIGH": "⚠️ **HIGH RISK**",
        "MEDIUM": "🟡 **MEDIUM RISK**",
        "LOW": "✅ **LOW RISK (PASSED)**",
    }
    badge = risk_badges.get(risk_score, f"ℹ️ **{risk_score}**")

    lines = [
        "## 🛡️ DevGuard AI — Security & Cloud Defense Audit",
        "",
        f"**Audit Status**: {badge}",
        f"**Summary**: {summary}",
        "",
    ]

    # Vulnerabilities Section
    if vulnerabilities:
        lines.append("### 🔍 Identified Security Vulnerabilities")
        lines.append("| Severity | Vulnerability Type | Description |")
        lines.append("| :--- | :--- | :--- |")
        for vuln in vulnerabilities:
            sev = vuln.get("severity", "UNKNOWN")
            vtype = vuln.get("type", "Security Finding")
            desc = vuln.get("description", "").replace("\n", " ")
            lines.append(f"| **{sev}** | `{vtype}` | {desc} |")
        lines.append("")
    else:
        lines.append("### 🔍 Vulnerability Scan")
        lines.append("✅ No known vulnerabilities, exposed network ports, or prompt injection flaws identified in this PR.")
        lines.append("")

    # Active Defense / Linode Cloud Firewall Shield Section
    if requires_firewall and firewall_result:
        fw_id = firewall_result.get("id", "N/A")
        label = firewall_result.get("label", "devguard-shield")
        linodes = firewall_result.get("devices", {}).get("linodes", [analysis.get("target_linode_id", "N/A")])
        mock_indicator = " *(Simulated Shield)*" if firewall_result.get("mock") else ""

        lines.append("### 🔒 Active Defense Action Triggered")
        lines.append(f"🛡️ **Linode Cloud Firewall Auto-Provisioned{mock_indicator}**")
        lines.append(f"- **Firewall ID**: `{fw_id}` (`{label}`)")
        lines.append("- **Inbound Policy**: `DROP` *(all unauthorized traffic dropped)*")
        lines.append("- **Permitted Ingress**: `TCP Port 443` *(HTTPS only)*")
        lines.append(f"- **Protected Compute**: Linode Instance ID(s) `{linodes}`")
        lines.append("- **Status**: Active & Enforced")
        lines.append("")
    elif requires_firewall:
        lines.append("### 🔒 Active Defense Action Triggered")
        lines.append("⚠️ Cloud Firewall enforcement recommended for target Linode instance.")
        lines.append("")

    # Remediation Diff Section
    if remediation_diff and remediation_diff.strip():
        lines.append("### 🛠️ Suggested Remediation Patch")
        lines.append("```diff")
        lines.append(remediation_diff.strip())
        lines.append("```")
        lines.append("")

    # Footer
    lines.append("---")
    lines.append("*Automated security audit powered by **DevGuard AI** on the **Akamai Cloud & Hosted AI Inference** platform.*")

    return "\n".join(lines)


class GitHubClient:
    """Async client interacting with the GitHub REST API v3."""

    def __init__(self, token: str | None = None, mock_mode: bool | None = None):
        self.token = token or settings.GITHUB_TOKEN
        self.mock_mode = settings.is_github_mock if mock_mode is None else mock_mode
        self.base_url = GITHUB_API_BASE

    async def get_pr_diff(self, owner: str, repo: str, pull_number: int, fallback_diff: str = "") -> str:
        """Retrieves raw unified diff for a pull request."""
        if self.mock_mode:
            logger.info("GitHubClient in MOCK_MODE: returning local or fallback diff for PR #%s", pull_number)
            if fallback_diff:
                return fallback_diff
            return (
                "diff --git a/compose.yaml b/compose.yaml\n"
                "index 1234567..89abcdef 100644\n"
                "--- a/compose.yaml\n"
                "+++ b/compose.yaml\n"
                "@@ -5,2 +5,4 @@ services:\n"
                "   agent:\n"
                "+    ports:\n"
                '+      - "0.0.0.0:22:22"\n'
                "+    linode_id = 12345\n"
            )

        headers = {
            "Accept": "application/vnd.github.v3.diff",
            "User-Agent": "DevGuard-AI/1.0",
        }
        if self.token and self.token != "mock_github":
            headers["Authorization"] = f"token {self.token}"
        url = f"{self.base_url}/repos/{owner}/{repo}/pulls/{pull_number}"

        try:
            logger.info("Fetching PR diff from GitHub API: %s", url)
            async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
                response = await client.get(url, headers=headers)

            if response.status_code == 200:
                logger.info("Successfully fetched PR #%s diff (%d bytes)", pull_number, len(response.text))
                return response.text
            else:
                logger.warning(
                    "GitHub API diff fetch returned HTTP %s: %s. Using fallback diff.",
                    response.status_code,
                    response.text[:200],
                )
                return fallback_diff
        except Exception as exc:
            logger.warning("Error fetching diff from GitHub: %s. Using fallback diff.", exc)
            return fallback_diff

    async def post_pr_comment(
        self,
        owner: str,
        repo: str,
        pull_number: int,
        comment_body: str,
    ) -> dict[str, Any]:
        """Publishes an issue comment to the PR discussion thread."""
        if self.mock_mode:
            logger.info("GitHubClient in MOCK_MODE: recording mock comment on PR #%s", pull_number)
            return {
                "id": 9001,
                "html_url": f"https://github.com/{owner}/{repo}/pull/{pull_number}#issuecomment-9001",
                "body": comment_body,
                "created_at": "mock_timestamp",
                "mock": True,
            }

        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "DevGuard-AI/1.0",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token and self.token != "mock_github":
            headers["Authorization"] = f"token {self.token}"
        url = f"{self.base_url}/repos/{owner}/{repo}/issues/{pull_number}/comments"

        try:
            logger.info("Posting comment to GitHub PR #%s: %s", pull_number, url)
            async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
                response = await client.post(url, headers=headers, json={"body": comment_body})

            if response.status_code in (200, 201):
                data = response.json()
                logger.info("Successfully posted review comment on GitHub PR #%s: %s", pull_number, data.get("html_url"))
                data["mock"] = False
                return data
            else:
                logger.warning(
                    "GitHub API comment returned HTTP %s: %s. Emulating comment response.",
                    response.status_code,
                    response.text[:200],
                )
                return {
                    "id": 9001,
                    "html_url": f"https://github.com/{owner}/{repo}/pull/{pull_number}#simulated-comment",
                    "body": comment_body,
                    "mock": True,
                    "error": f"HTTP {response.status_code}",
                }
        except Exception as exc:
            logger.warning("Error posting comment to GitHub: %s. Emulating comment response.", exc)
            return {
                "id": 9001,
                "html_url": f"https://github.com/{owner}/{repo}/pull/{pull_number}#simulated-comment",
                "body": comment_body,
                "mock": True,
                "error": str(exc),
            }


github_client = GitHubClient()
