"""DevGuard AI - AI Security Analysis Engine.

Connects to Akamai's Hosted AI Inference Service to perform real-time
AppSec & cloud infrastructure auditing of incoming PR diffs. Returns
strict JSON findings, risk scores, remediation diffs, and triggers active defense.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Literal
import httpx
from pydantic import BaseModel, Field

from app.config import settings

logger = logging.getLogger("devguard.ai_engine")

RiskScoreType = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]


class VulnerabilityItem(BaseModel):
    type: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    description: str


class SecurityAnalysisResult(BaseModel):
    risk_score: RiskScoreType
    summary: str
    vulnerabilities: list[VulnerabilityItem] = Field(default_factory=list)
    remediation_diff: str = ""
    requires_firewall_action: bool = False
    target_linode_id: int | None = None


SYSTEM_PROMPT = """You are DevGuard AI, an autonomous DevSecOps and Cloud Infrastructure defense auditor for Akamai Cloud and Linode compute environments.
Your task is to analyze the provided Git Pull Request diff for security risks, infrastructure exposure, prompt injections, credential leaks, and code vulnerabilities.

You MUST respond with ONLY a valid, raw JSON object matching the following exact JSON structure without markdown formatting, code fences, or explanatory commentary outside the JSON:
{
  "risk_score": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "summary": "Short finding summary",
  "vulnerabilities": [
    {"type": "Prompt Injection / Exposed Port / Hardcoded Secret / Insecure Binding", "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW", "description": "Specific finding explanation"}
  ],
  "remediation_diff": "Suggested unified git diff patch fixing the vulnerability",
  "requires_firewall_action": true | false,
  "target_linode_id": 12345
}

Decision Rules:
1. "risk_score" MUST be one of: "CRITICAL", "HIGH", "MEDIUM", "LOW".
2. If any exposed ports (e.g. 0.0.0.0:22, 0.0.0.0:8000, 0.0.0.0:6379), insecure public host listeners, prompt injection vectors into LLM system prompts, or critical remote code executions are detected, set "requires_firewall_action": true.
3. If no target_linode_id is specified in the code, extract any Linode ID mentioned or use 12345 as the default target.
4. "remediation_diff" MUST provide a valid unified git diff patch resolving the identified security issues.
5. If the diff is safe, return "risk_score": "LOW", "requires_firewall_action": false, empty vulnerabilities list, and an empty remediation_diff.
"""


def _extract_linode_id(diff_text: str, fallback: int = 12345) -> int:
    """Extract Linode instance ID from diff or use default."""
    match = re.search(r'(?:linode[-_]?id|linode)\s*[:=]\s*(\d{4,9})', diff_text, re.IGNORECASE)
    if match:
        try:
            return int(match.group(1))
        except ValueError:
            pass
    return fallback


def _clean_json_response(content: str) -> str:
    """Strip markdown fences and whitespace from model response."""
    text = content.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text)
    # Search for first { to last }
    first_brace = text.find("{")
    last_brace = text.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        text = text[first_brace : last_brace + 1]
    return text.strip()


def _analyze_mock_diff(diff_text: str, pr_title: str = "", pr_context: dict[str, Any] | None = None) -> SecurityAnalysisResult:
    """Deterministic offline security analysis for test suites and offline mock mode."""
    vulnerabilities: list[VulnerabilityItem] = []
    requires_firewall_action = False
    remediation_patches: list[str] = []
    linode_id = _extract_linode_id(diff_text, fallback=(pr_context or {}).get("linode_id", 12345))

    lower_diff = diff_text.lower()

    # 1. Exposed Port Detection (SSH, HTTP, Database, Debug)
    if any(pat in diff_text for pat in ["0.0.0.0:22", "0.0.0.0:8000", "0.0.0.0:6379", "0.0.0.0:3306", "0.0.0.0:5432", "0.0.0.0:27017"]) or \
       re.search(r'ports:\s*-\s*["\'](?:22|8000|6379|3306|5432):', diff_text) or \
       re.search(r'EXPOSE\s+(?:22|6379|3306|5432)', diff_text):
        vulnerabilities.append(VulnerabilityItem(
            type="Exposed Insecure Port",
            severity="CRITICAL",
            description="Production service exposes sensitive or administrative ports (SSH/Debug/DB) to public ingress (0.0.0.0) without zero-trust network boundaries."
        ))
        requires_firewall_action = True
        remediation_patches.append(
            "--- a/compose.yaml\n"
            "+++ b/compose.yaml\n"
            "@@ -5,2 +5,2 @@\n"
            "-    ports:\n"
            '-      - "0.0.0.0:22:22"\n'
            "+    # Restricted: Access protected via Akamai Cloud Firewall & VPN\n"
            '+    expose:\n'
            '+      - "22"'
        )

    # 2. Prompt Injection Vector Detection
    if re.search(r'(?:system_prompt|messages).*?(?:format|f[\"\']).*?(?:user_input|user_prompt|message|query)', diff_text, re.IGNORECASE) or \
       "role\": \"system\", \"content\": f\"" in diff_text or \
       "role': 'system', 'content': f'" in diff_text:
        vulnerabilities.append(VulnerabilityItem(
            type="Prompt Injection Vulnerability",
            severity="HIGH",
            description="Untrusted user input interpolated directly into AI system prompt without delimiter boundaries or input sanitization, allowing prompt injection."
        ))
        requires_firewall_action = True
        remediation_patches.append(
            "--- a/agent/brain.py\n"
            "+++ b/agent/brain.py\n"
            "@@ -15,2 +15,5 @@\n"
            "-    system_prompt = f\"System instructions: {user_input}\"\n"
            "+    # DevGuard Sanitization: keep system instructions isolated\n"
            "+    sanitized_input = sanitize_user_input(user_input)\n"
            "+    messages = [{'role': 'system', 'content': SYSTEM_PROMPT},\n"
            "+                {'role': 'user', 'content': sanitized_input}]"
        )

    # 3. Remote Code Execution / Insecure Execution
    if any(pattern in diff_text for pattern in ["os.system(", "subprocess.Popen(", "subprocess.run(shell=True", "eval(", "exec("]):
        vulnerabilities.append(VulnerabilityItem(
            type="Command Injection / Arbitrary Code Execution",
            severity="CRITICAL",
            description="Unsafe command invocation or code evaluation detected (eval/exec/os.system), exposing instance to remote code execution."
        ))
        requires_firewall_action = True

    # 4. Hardcoded Secrets
    if re.search(r'(?:api_key|secret_key|private_key|token|password)\s*=\s*["\'][A-Za-z0-9_\-]{16,}["\']', diff_text, re.IGNORECASE):
        vulnerabilities.append(VulnerabilityItem(
            type="Hardcoded Secret / API Token Leak",
            severity="HIGH",
            description="Hardcoded credentials or API keys committed to source code. Secrets must be loaded exclusively via environment variables."
        ))

    # Determine overall risk score and summary
    if any(v.severity == "CRITICAL" for v in vulnerabilities):
        risk_score: RiskScoreType = "CRITICAL"
        summary = f"Critical security vulnerabilities detected in PR: {len(vulnerabilities)} high-impact issue(s) require active defense mitigation."
    elif any(v.severity == "HIGH" for v in vulnerabilities):
        risk_score = "HIGH"
        summary = f"High-risk vulnerabilities detected in PR: {len(vulnerabilities)} issue(s) identified including potential infrastructure exposure."
    elif any(v.severity == "MEDIUM" for v in vulnerabilities):
        risk_score = "MEDIUM"
        summary = f"Medium-risk warnings identified: {len(vulnerabilities)} issue(s) detected."
    else:
        risk_score = "LOW"
        summary = "Security scan passed: No critical vulnerabilities, exposed ports, or prompt injection flaws detected."

    remediation_diff = "\n\n".join(remediation_patches) if remediation_patches else ""

    return SecurityAnalysisResult(
        risk_score=risk_score,
        summary=summary,
        vulnerabilities=vulnerabilities,
        remediation_diff=remediation_diff,
        requires_firewall_action=requires_firewall_action,
        target_linode_id=linode_id if requires_firewall_action else None,
    )


class AIEngine:
    """Client for Akamai Hosted AI Inference service performing PR security audits."""

    def __init__(self, endpoint: str | None = None, api_key: str | None = None, mock_mode: bool | None = None):
        self.endpoint = endpoint or settings.INFERENCE_ENDPOINT
        self.api_key = api_key or settings.INFERENCE_API_KEY
        self.mock_mode = settings.is_inference_mock if mock_mode is None else mock_mode

    async def analyze_diff(
        self,
        diff_text: str,
        pr_title: str = "",
        pr_context: dict[str, Any] | None = None,
    ) -> SecurityAnalysisResult:
        """Audits a pull request diff using Akamai Hosted AI Inference or mock fallback."""
        if not diff_text or not diff_text.strip():
            return SecurityAnalysisResult(
                risk_score="LOW",
                summary="Empty pull request diff: No modifications to audit.",
                vulnerabilities=[],
                remediation_diff="",
                requires_firewall_action=False,
                target_linode_id=None,
            )

        if self.mock_mode:
            logger.info("AIEngine operating in MOCK_MODE - executing heuristic analysis.")
            return _analyze_mock_diff(diff_text, pr_title=pr_title, pr_context=pr_context)

        # Live inference via Akamai Hosted AI endpoint
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        user_content = (
            f"Pull Request Title: {pr_title or 'Untitled PR'}\n"
            f"Metadata: {json.dumps(pr_context or {})}\n\n"
            f"--- GIT DIFF BEGIN ---\n"
            f"{diff_text}\n"
            f"--- GIT DIFF END ---"
        )

        payload = {
            "model": "hackathon-chat",
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
            ],
            "temperature": 0.1,
            "max_tokens": 1500,
        }

        try:
            logger.info("Dispatching PR security audit to Akamai Hosted AI Inference endpoint: %s", self.endpoint)
            async with httpx.AsyncClient(timeout=35.0) as client:
                response = await client.post(self.endpoint, headers=headers, json=payload)

            if response.status_code == 200:
                data = response.json()
                raw_reply = data.get("choices", [{}])[0].get("message", {}).get("content", "")
                cleaned = _clean_json_response(raw_reply)
                parsed = json.loads(cleaned)

                # Validate against schema
                result = SecurityAnalysisResult(**parsed)
                logger.info("Successfully audited PR via Akamai Inference. Risk Score: %s", result.risk_score)
                return result
            else:
                logger.warning(
                    "Akamai Inference endpoint returned HTTP %s: %s. Falling back to heuristic analyzer.",
                    response.status_code,
                    response.text[:200],
                )
                return _analyze_mock_diff(diff_text, pr_title=pr_title, pr_context=pr_context)

        except Exception as exc:
            logger.warning("Error communicating with Akamai Hosted AI service: %s. Falling back to heuristic analysis.", exc)
            return _analyze_mock_diff(diff_text, pr_title=pr_title, pr_context=pr_context)


ai_engine = AIEngine()
