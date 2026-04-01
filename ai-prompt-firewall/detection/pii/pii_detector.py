"""
PII Detection Layer — Microsoft Presidio integration.
=====================================================
Scans prompts for personally identifiable information:
SSNs, credit cards, emails, phone numbers, names, addresses, etc.
Flags any prompt containing PII to prevent data leakage to LLMs.
"""

import re
from typing import Optional

from models import DetectionLayer, ScanResult, ThreatCategory

# Lazy-load Presidio to avoid import-time model downloads
_analyzer: Optional[object] = None

REGEX_FALLBACKS = {
    "US_SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "CREDIT_CARD": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    "EMAIL_ADDRESS": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    "PHONE_NUMBER": re.compile(
        r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b"
    ),
}


def _get_analyzer():
    """Lazy singleton for the Presidio analyzer engine."""
    global _analyzer
    if _analyzer is None:
        try:
            from presidio_analyzer import AnalyzerEngine
            _analyzer = AnalyzerEngine()
        except Exception:
            _analyzer = False
    return _analyzer


# PII entity types and their severity weights
PII_SEVERITY_MAP = {
    "CREDIT_CARD": 0.95,
    "US_SSN": 0.95,
    "US_BANK_NUMBER": 0.90,
    "IBAN_CODE": 0.90,
    "MEDICAL_LICENSE": 0.85,
    "US_PASSPORT": 0.85,
    "US_DRIVER_LICENSE": 0.85,
    "CRYPTO": 0.80,
    "IP_ADDRESS": 0.60,
    "EMAIL_ADDRESS": 0.70,
    "PHONE_NUMBER": 0.70,
    "PERSON": 0.50,
    "LOCATION": 0.40,
    "DATE_TIME": 0.20,
    "NRP": 0.30,  # nationality/religious/political group
}

# Entities that alone should trigger a block
HIGH_RISK_ENTITIES = {
    "CREDIT_CARD", "US_SSN", "US_BANK_NUMBER", "IBAN_CODE",
    "US_PASSPORT", "US_DRIVER_LICENSE", "MEDICAL_LICENSE",
}


class PIIDetector:
    """
    Wraps Microsoft Presidio to detect PII in prompts.
    Returns a ScanResult with the highest-risk entity found.
    """

    def __init__(self, score_threshold: float = 0.5):
        self.score_threshold = score_threshold

    def scan(self, prompt: str) -> ScanResult:
        """Analyze prompt for PII entities."""
        analyzer = _get_analyzer()
        entities_found: list[dict] = []

        if analyzer:
            results = analyzer.analyze(
                text=prompt,
                language="en",
                score_threshold=self.score_threshold,
            )
            for result in results:
                entities_found.append(
                    self._build_entity(
                        prompt=prompt,
                        entity_type=result.entity_type,
                        start=result.start,
                        end=result.end,
                        score=result.score,
                    )
                )

        for entity_type, pattern in REGEX_FALLBACKS.items():
            for match in pattern.finditer(prompt):
                if self._has_overlap(entities_found, entity_type, match.start(), match.end()):
                    continue
                entities_found.append(
                    self._build_entity(
                        prompt=prompt,
                        entity_type=entity_type,
                        start=match.start(),
                        end=match.end(),
                        score=1.0,
                    )
                )

        if not entities_found:
            return ScanResult(layer=DetectionLayer.PII_DETECTOR, triggered=False)

        highest = max(entities_found, key=lambda entity: entity["combined_score"])
        highest_severity = highest["combined_score"]
        highest_entity = highest["entity_type"]

        # Determine if this should trigger
        has_high_risk = any(e["entity_type"] in HIGH_RISK_ENTITIES for e in entities_found)
        triggered = has_high_risk or highest_severity >= 0.60
        confidence = max(highest_severity, 1.0 if has_high_risk else 0.0)

        return ScanResult(
            layer=DetectionLayer.PII_DETECTOR,
            triggered=triggered,
            category=ThreatCategory.PII_LEAK if triggered else ThreatCategory.CLEAN,
            confidence=round(confidence, 4),
            matched_pattern=highest_entity,
            details={
                "entities_found": entities_found,
                "total_entities": len(entities_found),
                "has_high_risk_entity": has_high_risk,
            },
        )

    @staticmethod
    def _build_entity(prompt: str, entity_type: str, start: int, end: int, score: float) -> dict:
        severity = PII_SEVERITY_MAP.get(entity_type, 0.50)
        combined = score * severity
        return {
            "entity_type": entity_type,
            "start": start,
            "end": end,
            "presidio_score": round(score, 4),
            "severity": severity,
            "combined_score": round(combined, 4),
            "text_snippet": prompt[start:end][:4] + "***",
        }

    @staticmethod
    def _has_overlap(entities_found: list[dict], entity_type: str, start: int, end: int) -> bool:
        return any(
            entity["entity_type"] == entity_type
            and not (end <= entity["start"] or start >= entity["end"])
            for entity in entities_found
        )
