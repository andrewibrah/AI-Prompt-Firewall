"""
Core data models shared across firewall layers.
Every detection layer returns a ScanResult.
The proxy aggregates them into a FirewallVerdict.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class ThreatCategory(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    PII_LEAK = "pii_leak"
    SYSTEM_PROMPT_EXTRACTION = "system_prompt_extraction"
    ROLE_MANIPULATION = "role_manipulation"
    ENCODING_ATTACK = "encoding_attack"
    SEMANTIC_THREAT = "semantic_threat"
    CLEAN = "clean"


class DetectionLayer(str, Enum):
    RULE_ENGINE = "rule_engine"
    PII_DETECTOR = "pii_detector"
    SEMANTIC_SIMILARITY = "semantic_similarity"


class ScanResult(BaseModel):
    """Output from a single detection layer."""
    layer: DetectionLayer
    triggered: bool = False
    category: ThreatCategory = ThreatCategory.CLEAN
    confidence: float = 0.0  # 0.0 to 1.0
    matched_pattern: Optional[str] = None
    details: dict = Field(default_factory=dict)


class Verdict(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    FLAG = "flag"  # monitor mode — log but don't block


class FirewallVerdict(BaseModel):
    """Aggregated decision from all layers."""
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    verdict: Verdict = Verdict.ALLOW
    prompt: str
    scan_results: list[ScanResult] = Field(default_factory=list)
    highest_confidence: float = 0.0
    primary_category: ThreatCategory = ThreatCategory.CLEAN
    blocked_by: Optional[DetectionLayer] = None

    def should_block(self, threshold: float, mode: str) -> bool:
        """Determine final action based on mode and threshold."""
        if mode == "passthrough":
            return False

        blocking_results = [
            result
            for result in self.scan_results
            if result.triggered and result.confidence >= threshold
        ]
        if blocking_results:
            strongest = max(blocking_results, key=lambda result: result.confidence)
            self.verdict = Verdict.BLOCK if mode == "enforce" else Verdict.FLAG
            self.highest_confidence = strongest.confidence
            self.primary_category = strongest.category
            self.blocked_by = strongest.layer
            return mode == "enforce"
        return False


class PromptRequest(BaseModel):
    """Incoming request from client."""
    model_config = ConfigDict(extra="allow")

    messages: list[dict]  # OpenAI-format messages
    model: Optional[str] = None
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
