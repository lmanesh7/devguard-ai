"""Unit & Integration tests for DevGuard AI components."""
import asyncio
import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.ai_engine import ai_engine
from app.linode_firewall import linode_firewall_client
from app.github_client import github_client, format_security_review_comment
from app.main import app


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def test_config_settings():
    """Verify settings defaults and attributes."""
    assert hasattr(settings, "INFERENCE_ENDPOINT")
    assert hasattr(settings, "INFERENCE_API_KEY")
    assert hasattr(settings, "GITHUB_TOKEN")
    assert hasattr(settings, "LINODE_TOKEN")
    assert hasattr(settings, "VALKEY_HOST")
    assert hasattr(settings, "MOCK_MODE")
    assert settings.is_linode_mock is True
    assert settings.is_github_mock is True


def test_ai_engine_vulnerable_diff():
    """Verify AI Engine catches exposed ports and prompt injection."""
    diff = """
+ ports:
+   - "0.0.0.0:22:22"
+ linode_id = 12345
+ system_prompt = f"System: {user_input}"
"""
    result = asyncio.run(ai_engine.analyze_diff(diff))
    assert result.risk_score in ("CRITICAL", "HIGH")
    assert result.requires_firewall_action is True
    assert result.target_linode_id == 12345
    assert len(result.vulnerabilities) >= 2
    assert "--- a/compose.yaml" in result.remediation_diff or "--- a/agent/brain.py" in result.remediation_diff


def test_ai_engine_clean_diff():
    """Verify AI Engine passes clean safe diffs."""
    diff = """
+ # Safe comment
+ def add(a: int, b: int) -> int:
+     return a + b
"""
    result = asyncio.run(ai_engine.analyze_diff(diff))
    assert result.risk_score == "LOW"
    assert result.requires_firewall_action is False
    assert len(result.vulnerabilities) == 0


def test_linode_firewall_zero_trust():
    """Verify zero-trust firewall payload structure."""
    result = asyncio.run(linode_firewall_client.create_zero_trust_firewall(54321))
    assert result["rules"]["inbound_policy"] == "DROP"
    assert result["devices"]["linodes"] == [54321]
    inbound_rules = result["rules"]["inbound"]
    assert any(r.get("ports") == "443" and r.get("protocol") == "TCP" for r in inbound_rules)


def test_github_client_mock():
    """Verify GitHub client diff and comment posting."""
    diff = asyncio.run(github_client.get_pr_diff("owner", "repo", 99))
    assert "compose.yaml" in diff

    comment = format_security_review_comment(
        {
            "risk_score": "CRITICAL",
            "summary": "Exposed port found",
            "vulnerabilities": [{"type": "Exposed Port", "severity": "CRITICAL", "description": "0.0.0.0:22"}],
            "requires_firewall_action": True,
            "target_linode_id": 12345,
            "remediation_diff": "--- a\n+++ b",
        },
        firewall_result={"id": 998877, "label": "shield", "mock": True},
    )
    assert "DevGuard AI" in comment
    assert "CRITICAL RISK" in comment
    assert "DROP" in comment

    post_resp = asyncio.run(github_client.post_pr_comment("owner", "repo", 99, comment))
    assert post_resp["id"] == 9001
    assert post_resp["mock"] is True


def test_api_health(client):
    """Verify health endpoint."""
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["service"] == "DevGuard AI"
    assert "inference" in data
    assert "linode_firewall" in data


def test_api_dashboard(client):
    """Verify static dashboard delivery."""
    resp = client.get("/")
    assert resp.status_code == 200
    assert "DevGuard AI" in resp.text


def test_webhook_vulnerable_pr(client):
    """Verify POST /webhook/github triggers active defense for vulnerable PR."""
    payload = {
        "action": "opened",
        "pull_request": {"number": 10, "title": "Expose SSH port"},
        "repository": {"full_name": "test-org/test-repo"},
        "diff_content": "+ ports:\n+   - 0.0.0.0:22:22\n+ linode_id = 77777",
    }
    resp = client.post("/webhook/github", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    audit = data["audit"]
    assert audit["security_analysis"]["risk_score"] == "CRITICAL"
    assert audit["firewall_action"] is not None
    assert audit["firewall_action"]["devices"]["linodes"] == [77777]


def test_webhook_safe_pr(client):
    """Verify POST /webhook/github passes safe PR without firewall action."""
    payload = {
        "action": "opened",
        "pull_request": {"number": 11, "title": "Refactor docs"},
        "repository": {"full_name": "test-org/test-repo"},
        "diff_content": "+ # Just a documentation line",
    }
    resp = client.post("/webhook/github", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    audit = data["audit"]
    assert audit["security_analysis"]["risk_score"] == "LOW"
    assert audit["firewall_action"] is None


def test_direct_audit_api(client):
    """Verify POST /api/audit endpoint."""
    resp = client.post(
        "/api/audit",
        json={"diff": "+ ports:\n+   - 0.0.0.0:22:22", "title": "Manual audit", "linode_id": 12345},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert data["audit"]["security_analysis"]["requires_firewall_action"] is True


def test_websocket_stream(client):
    """Verify WebSocket connection and message receipt."""
    with client.websocket_connect("/ws") as ws:
        msg = ws.receive_json()
        assert msg["event"] == "CONNECTED"
        assert "DevGuard AI" in msg["service"]
        ws.send_json({"action": "ping"})
        pong = ws.receive_json()
        assert pong["event"] == "PONG"
