"""
AI Prompt Firewall — FastAPI Proxy Server
==========================================
Sits between client and LLM API.
Every prompt passes through: rule engine → PII detector → semantic similarity.
Blocked prompts never reach the LLM. All decisions are audit-logged.
"""

from contextlib import asynccontextmanager

from pathlib import Path

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from config import settings
from models import (
    FirewallVerdict,
    PromptRequest,
    Verdict,
)
from engine.rule_engine import RuleEngine
from detection.pii.pii_detector import PIIDetector
from detection.semantic.semantic_detector import SemanticDetector
from audit_logging.audit_logger import AuditLogger


# ── Lifespan: init all layers once at startup ──────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    app.state.rule_engine = RuleEngine(rules_dir=settings.rules_dir)
    app.state.pii_detector = PIIDetector()
    app.state.semantic_detector = None
    if settings.semantic_enabled:
        app.state.semantic_detector = SemanticDetector(
            threat_store_path=settings.threat_store_path,
            threshold=settings.block_threshold,
        )
    app.state.audit_logger = AuditLogger(db_path=settings.db_path)
    await app.state.audit_logger.init_db()
    app.state.http_client = httpx.AsyncClient(timeout=30.0)
    yield
    # Shutdown
    await app.state.http_client.aclose()
    await app.state.audit_logger.close()


app = FastAPI(
    title="AI Prompt Firewall",
    version="1.0.0",
    description="Intercepts and analyzes prompts before they reach the LLM.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Serve dashboard static files ──────────────────────────────────
_dashboard_dir = Path(__file__).resolve().parent.parent / "dashboard"
app.mount("/dashboard", StaticFiles(directory=str(_dashboard_dir), html=True), name="dashboard")


@app.get("/")
async def root():
    """Redirect browser visitors to the dashboard."""
    return RedirectResponse(url="/dashboard/index.html")


# ── Health check ───────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {
        "status": "operational",
        "mode": settings.firewall_mode,
        "layers": {
            "rule_engine": settings.rule_engine_enabled,
            "pii_detector": settings.pii_enabled,
            "semantic": settings.semantic_enabled,
        },
    }


# ── Main proxy endpoint ───────────────────────────────────────────
@app.post("/v1/chat/completions")
async def proxy_completion(request: Request):
    """
    Drop-in replacement for OpenAI's /v1/chat/completions.
    Client sends the same payload — firewall scans it first.
    """
    body = await request.json()
    prompt_req = PromptRequest(**body)

    # Extract the user-facing prompt text for scanning
    user_prompt = _extract_user_prompt(prompt_req.messages)

    # ── Run all detection layers ──────────────────────────────
    verdict = FirewallVerdict(prompt=user_prompt)

    if settings.rule_engine_enabled:
        rule_result = app.state.rule_engine.scan(user_prompt)
        verdict.scan_results.append(rule_result)

    if settings.pii_enabled:
        pii_result = app.state.pii_detector.scan(user_prompt)
        verdict.scan_results.append(pii_result)

    if settings.semantic_enabled and app.state.semantic_detector is not None:
        semantic_result = app.state.semantic_detector.scan(user_prompt)
        verdict.scan_results.append(semantic_result)

    # ── Decide: block or forward ──────────────────────────────
    should_block = verdict.should_block(
        threshold=settings.block_threshold,
        mode=settings.firewall_mode,
    )

    # ── Audit log (always, regardless of decision) ────────────
    await app.state.audit_logger.log(verdict)

    if should_block:
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "message": "Prompt blocked by AI Firewall",
                    "type": "firewall_block",
                    "request_id": verdict.request_id,
                    "category": verdict.primary_category.value,
                    "confidence": round(verdict.highest_confidence, 4),
                    "blocked_by": verdict.blocked_by.value if verdict.blocked_by else None,
                },
            },
        )

    # ── Forward to LLM ────────────────────────────────────────
    try:
        upstream_payload = body.copy()
        upstream_payload["model"] = prompt_req.model or settings.llm_model
        llm_response = await app.state.http_client.post(
            settings.llm_api_url,
            headers={
                "Authorization": f"Bearer {settings.llm_api_key}",
                "Content-Type": "application/json",
            },
            json=upstream_payload,
        )
        return JSONResponse(
            status_code=llm_response.status_code,
            content=llm_response.json(),
        )
    except httpx.RequestError as e:
        return JSONResponse(
            status_code=502,
            content={"error": {"message": f"LLM upstream error: {str(e)}"}},
        )


# ── Dashboard data endpoints ──────────────────────────────────────
@app.post("/api/scan")
async def scan_prompt(request: Request):
    """
    Scan-only endpoint for the dashboard test panel.
    Runs all detection layers against the prompt but does NOT forward to the LLM.
    """
    body = await request.json()
    raw_prompt = body.get("prompt", "").strip()
    if not raw_prompt:
        return JSONResponse(
            status_code=400,
            content={"error": "prompt is required"},
        )

    verdict = FirewallVerdict(prompt=raw_prompt)

    if settings.rule_engine_enabled:
        rule_result = app.state.rule_engine.scan(raw_prompt)
        verdict.scan_results.append(rule_result)

    if settings.pii_enabled:
        pii_result = app.state.pii_detector.scan(raw_prompt)
        verdict.scan_results.append(pii_result)

    if settings.semantic_enabled and app.state.semantic_detector is not None:
        semantic_result = app.state.semantic_detector.scan(raw_prompt)
        verdict.scan_results.append(semantic_result)

    should_block = verdict.should_block(
        threshold=settings.block_threshold,
        mode=settings.firewall_mode,
    )

    await app.state.audit_logger.log(verdict)

    return {
        "request_id": verdict.request_id,
        "verdict": verdict.verdict.value,
        "should_block": should_block,
        "primary_category": verdict.primary_category.value,
        "highest_confidence": round(verdict.highest_confidence, 4),
        "blocked_by": verdict.blocked_by.value if verdict.blocked_by else None,
        "scan_results": [r.model_dump(mode="json") for r in verdict.scan_results],
    }


@app.get("/api/audit/recent")
async def get_recent_logs(limit: int = 100):
    """Return recent audit entries for the dashboard."""
    rows = await app.state.audit_logger.get_recent(limit)
    return {"entries": rows}


@app.get("/api/audit/stats")
async def get_stats():
    """Aggregated stats for dashboard widgets."""
    stats = await app.state.audit_logger.get_stats()
    return stats


# ── Helpers ────────────────────────────────────────────────────────
def _extract_user_prompt(messages: list[dict]) -> str:
    """Pull out all user messages for scanning."""
    prompt_parts = []
    for msg in messages:
        if msg.get("role") != "user":
            continue
        content = msg.get("content", "")
        if isinstance(content, list):
            text_content = " ".join(
                part.get("text", "") for part in content if part.get("type") == "text"
            ).strip()
            if text_content:
                prompt_parts.append(text_content)
            continue
        if isinstance(content, str) and content.strip():
            prompt_parts.append(content)
    return "\n\n".join(prompt_parts)


if __name__ == "__main__":
    uvicorn.run(
        "api.server:app",
        host=settings.host,
        port=settings.port,
        reload=True,
        log_level=settings.log_level.lower(),
    )
