"""DevGuard AI - FastAPI Application Entrypoint.

Handles GitHub Pull Request webhooks, runs AI security auditing via Akamai Hosted AI,
provisions Zero-Trust Linode Cloud Firewalls on vulnerability detection, posts PR review
comments, and broadcasts real-time security events via WebSockets.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, Request, status
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
import redis.asyncio as redis

from app.ai_engine import ai_engine
from app.config import settings
from app.github_client import format_security_review_comment, github_client
from app.linode_firewall import linode_firewall_client

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("devguard.main")

STATIC_DIR = Path(__file__).parent / "static"
DASHBOARD_FILE = STATIC_DIR / "index.html"


# --- WEBSOCKET EVENT MANAGER ---
class WebSocketManager:
    """Manages active WebSocket client connections and broadcasts live audit events."""

    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info("WebSocket client connected. Total clients: %d", len(self.active_connections))

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info("WebSocket client disconnected. Total clients: %d", len(self.active_connections))

    async def broadcast(self, event: dict[str, Any]):
        """Broadcasts an event JSON object to all currently connected WebSocket clients."""
        if not self.active_connections:
            return
        dead_connections: list[WebSocket] = []
        for connection in list(self.active_connections):
            try:
                await connection.send_json(event)
            except Exception as exc:
                logger.warning("Failed to send WebSocket message: %s", exc)
                dead_connections.append(connection)
        for dead in dead_connections:
            self.disconnect(dead)


ws_manager = WebSocketManager()


# --- VALKEY / MEMORY STORAGE ---
class AuditStore:
    """Stores security audit history in Valkey (Redis) with in-memory fallback."""

    def __init__(self):
        self.client: redis.Redis | None = None
        self.in_memory_history: list[dict[str, Any]] = []
        self.connected_valkey: bool = False

    async def connect(self):
        """Attempts connection to Valkey."""
        valkey_url = settings.VALKEY_URL or f"redis://{settings.VALKEY_HOST}:{settings.VALKEY_PORT}/0"
        try:
            self.client = redis.from_url(valkey_url, decode_responses=True, socket_connect_timeout=2)
            await self.client.ping()
            self.connected_valkey = True
            logger.info("Connected to Valkey at %s", valkey_url)
        except Exception as exc:
            self.connected_valkey = False
            logger.info("Valkey unavailable (%s). Using in-memory audit store.", exc)

    async def save_audit(self, audit_record: dict[str, Any]):
        """Persists an audit record to Valkey and in-memory cache."""
        self.in_memory_history.insert(0, audit_record)
        if len(self.in_memory_history) > 100:
            self.in_memory_history.pop()

        if self.connected_valkey and self.client:
            try:
                repo = audit_record.get("pull_request", {}).get("repo", "default")
                pr_num = audit_record.get("pull_request", {}).get("number", 0)
                key = f"devguard:audit:{repo}:{pr_num}"
                payload = json.dumps(audit_record)
                await self.client.set(key, payload, ex=86400)
                await self.client.lpush("devguard:history", payload)
                await self.client.ltrim("devguard:history", 0, 99)
            except Exception as exc:
                logger.warning("Error saving audit to Valkey: %s", exc)

    async def get_history(self, limit: int = 20) -> list[dict[str, Any]]:
        """Retrieves recent audit events."""
        if self.connected_valkey and self.client:
            try:
                raw_list = await self.client.lrange("devguard:history", 0, limit - 1)
                if raw_list:
                    return [json.loads(item) for item in raw_list]
            except Exception as exc:
                logger.warning("Error fetching history from Valkey: %s", exc)
        return self.in_memory_history[:limit]

    async def close(self):
        if self.client:
            await self.client.aclose()


audit_store = AuditStore()


# --- APPLICATION LIFECYCLE ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting DevGuard AI application...")
    logger.info("Akamai Inference Endpoint: %s (Mock: %s)", settings.INFERENCE_ENDPOINT, settings.is_inference_mock)
    logger.info("Linode API Token: %s (Mock: %s)", "SET" if not settings.is_linode_mock else "MOCK", settings.is_linode_mock)
    logger.info("GitHub Token: %s (Mock: %s)", "SET" if not settings.is_github_mock else "MOCK", settings.is_github_mock)
    await audit_store.connect()
    yield
    await audit_store.close()
    logger.info("DevGuard AI application shut down cleanly.")


app = FastAPI(
    title="DevGuard AI",
    description="Autonomous PR Security Auditor & Linode Cloud Firewall Active Defense",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- REQUEST & RESPONSE SCHEMAS ---
class DirectAuditRequest(BaseModel):
    diff: str = Field(description="Raw unified git diff to audit")
    title: str = Field(default="Manual Security Audit", description="PR or audit title")
    repo: str = Field(default="workshop/demo-repo", description="Repository full name")
    pr_number: int = Field(default=1, description="Pull Request number")
    linode_id: int | None = Field(default=None, description="Optional target Linode instance ID")


# --- CORE AUDIT PIPELINE ---
async def run_security_pipeline(
    owner: str,
    repo: str,
    pull_number: int,
    pr_title: str,
    diff_content: str = "",
    override_linode_id: int | None = None,
) -> dict[str, Any]:
    """Executes the full DevGuard AI pipeline:

    1. Fetch PR Diff (GitHub API)
    2. AI Security Audit (Akamai Hosted AI)
    3. Auto-Provision Zero-Trust Firewall (Linode API v4) if vulnerabilities detected
    4. Post Markdown Review Comment (GitHub REST API)
    5. Broadcast WebSocket progress events
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    repo_full = f"{owner}/{repo}"

    # Step 1: Webhook Received / Diff Fetching
    await ws_manager.broadcast({
        "event": "WEBHOOK_RECEIVED",
        "timestamp": timestamp,
        "repo": repo_full,
        "pr_number": pull_number,
        "title": pr_title,
        "message": f"Received pull request event for #{pull_number}: {pr_title}",
    })

    # Pull raw diff via GitHub client
    if not diff_content:
        await ws_manager.broadcast({
            "event": "DIFF_FETCHING",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "repo": repo_full,
            "pr_number": pull_number,
            "message": f"Downloading PR #{pull_number} diff via GitHub REST API...",
        })
        diff_content = await github_client.get_pr_diff(owner, repo, pull_number)

    # Step 2: AI Security Analysis
    await ws_manager.broadcast({
        "event": "ANALYZING_DIFF",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "repo": repo_full,
        "pr_number": pull_number,
        "diff_bytes": len(diff_content),
        "message": "Dispatching diff to Akamai Hosted AI Inference service for real-time AppSec audit...",
    })

    pr_context = {"owner": owner, "repo": repo, "pull_number": pull_number, "linode_id": override_linode_id}
    analysis = await ai_engine.analyze_diff(diff_content, pr_title=pr_title, pr_context=pr_context)
    analysis_dict = analysis.model_dump()

    await ws_manager.broadcast({
        "event": "ANALYSIS_COMPLETE",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "repo": repo_full,
        "pr_number": pull_number,
        "risk_score": analysis.risk_score,
        "vulnerabilities_count": len(analysis.vulnerabilities),
        "requires_firewall_action": analysis.requires_firewall_action,
        "summary": analysis.summary,
        "message": f"AI audit complete: Risk Score is {analysis.risk_score}. Firewall action required: {analysis.requires_firewall_action}",
    })

    # Step 3: Active Defense - Linode Cloud Firewall Auto-Provisioning
    firewall_result: dict[str, Any] | None = None
    if analysis.requires_firewall_action:
        target_linode = override_linode_id or analysis.target_linode_id or 12345

        await ws_manager.broadcast({
            "event": "PROVISIONING_FIREWALL",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "repo": repo_full,
            "pr_number": pull_number,
            "target_linode_id": target_linode,
            "message": f"🚨 Vulnerability detected! Auto-provisioning Zero-Trust Linode Cloud Firewall for Linode ID {target_linode}...",
        })

        firewall_result = await linode_firewall_client.create_zero_trust_firewall(target_linode)

        await ws_manager.broadcast({
            "event": "FIREWALL_PROVISIONED",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "repo": repo_full,
            "pr_number": pull_number,
            "firewall_id": firewall_result.get("id"),
            "firewall_label": firewall_result.get("label"),
            "policy": "DROP",
            "ports_allowed": "443 TCP",
            "target_linode_id": target_linode,
            "mock": firewall_result.get("mock", False),
            "message": f"✅ Zero-Trust Cloud Firewall {firewall_result.get('id')} provisioned! Inbound DROP, port 443 permitted.",
        })

    # Step 4: Publish Review Comment to GitHub PR
    review_markdown = format_security_review_comment(analysis_dict, firewall_result)

    await ws_manager.broadcast({
        "event": "POSTING_REVIEW",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "repo": repo_full,
        "pr_number": pull_number,
        "message": "Posting automated DevGuard AI security review to GitHub PR thread...",
    })

    comment_result = await github_client.post_pr_comment(owner, repo, pull_number, review_markdown)

    await ws_manager.broadcast({
        "event": "REVIEW_POSTED",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "repo": repo_full,
        "pr_number": pull_number,
        "comment_id": comment_result.get("id"),
        "comment_url": comment_result.get("html_url"),
        "message": f"DevGuard AI security review published to GitHub PR #{pull_number}.",
    })

    # Step 5: Save Record to Valkey
    audit_record = {
        "timestamp": timestamp,
        "pull_request": {
            "owner": owner,
            "repo": repo,
            "number": pull_number,
            "title": pr_title,
        },
        "security_analysis": analysis_dict,
        "firewall_action": firewall_result,
        "github_comment": comment_result,
        "diff_preview": diff_content[:500] if diff_content else "",
    }
    await audit_store.save_audit(audit_record)

    return audit_record


# --- API ROUTES ---

@app.post("/webhook/github")
async def github_webhook(
    request: Request,
    background: BackgroundTasks,
):
    # GitHub sends a JSON payload; we need the raw body for signature verification
    payload = await request.json()
    event_type = request.headers.get("X-GitHub-Event", "")

    if event_type == "ping":
        return JSONResponse({"status": "pong"})

    # Immediately acknowledge receipt so GitHub sees a 202
    response = JSONResponse(
        {"detail": "accepted, processing in background"},
        status_code=status.HTTP_202_ACCEPTED,
    )

    # Parse payload and schedule pipeline as a background task
    repo_info = payload.get("repository", {})
    owner = repo_info.get("owner", {}).get("login", "")
    repo = repo_info.get("name", "")
    pr = payload.get("pull_request", {})
    pull_number = pr.get("number", 0)
    pr_title = pr.get("title", "")
    background.add_task(
        run_security_pipeline,
        owner=owner,
        repo=repo,
        pull_number=pull_number,
        pr_title=pr_title,
        diff_content="",
        override_linode_id=None,
    )
    return response

@app.post("/api/audit")
async def direct_audit(body: DirectAuditRequest) -> JSONResponse:
    """Direct API endpoint to audit an arbitrary diff on demand."""
    if "/" in body.repo:
        owner, repo = body.repo.split("/", 1)
    else:
        owner, repo = "developer", body.repo

    result = await run_security_pipeline(
        owner=owner,
        repo=repo,
        pull_number=body.pr_number,
        pr_title=body.title,
        diff_content=body.diff,
        override_linode_id=body.linode_id,
    )
    return JSONResponse(content={"status": "success", "audit": result})


@app.get("/api/history")
async def get_history(limit: int = 20) -> JSONResponse:
    """Returns recent audit history."""
    history = await audit_store.get_history(limit=limit)
    return JSONResponse(content={"count": len(history), "history": history})


@app.get("/health")
async def health() -> dict[str, Any]:
    """Health check endpoint showing current Akamai & DevGuard services state."""
    return {
        "status": "ok",
        "service": "DevGuard AI",
        "version": "1.0.0",
        "mock_mode": settings.MOCK_MODE,
        "inference": {
            "endpoint": settings.INFERENCE_ENDPOINT,
            "mock": settings.is_inference_mock,
        },
        "valkey": {
            "status": "connected" if audit_store.connected_valkey else "fallback_in_memory",
            "host": settings.VALKEY_HOST,
            "port": settings.VALKEY_PORT,
        },
        "linode_firewall": {
            "ready": True,
            "mock": settings.is_linode_mock,
        },
        "github_client": {
            "ready": True,
            "mock": settings.is_github_mock,
        },
    }


# --- WEBSOCKET ENDPOINTS ---

@app.websocket("/ws")
@app.websocket("/ws/events")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint broadcasting real-time DevGuard security audit events."""
    await ws_manager.connect(websocket)
    try:
        # Send initial welcome and recent events
        recent = await audit_store.get_history(limit=5)
        await websocket.send_json({
            "event": "CONNECTED",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "service": "DevGuard AI Live Event Stream",
            "recent_audits": recent,
        })
        while True:
            # Keep connection open and receive optional ping / commands
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("action") == "ping":
                    await websocket.send_json({"event": "PONG", "timestamp": datetime.now(timezone.utc).isoformat()})
            except Exception:
                pass
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as exc:
        logger.warning("WebSocket exception: %s", exc)
        ws_manager.disconnect(websocket)


# --- DASHBOARD UI ---

@app.get("/")
async def root():
    """Serves the interactive DevGuard AI dashboard."""
    if DASHBOARD_FILE.exists():
        return FileResponse(DASHBOARD_FILE)
    return HTMLResponse("<h1>DevGuard AI Backend Running</h1><p>Visit /health or /webhook/github</p>")
