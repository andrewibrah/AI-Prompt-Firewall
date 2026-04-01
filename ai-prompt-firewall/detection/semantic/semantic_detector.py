"""
Semantic Similarity Detector — sentence-transformers threat matching.
====================================================================
Embeds incoming prompts and compares against a vector store of known
adversarial patterns. Catches paraphrased attacks that regex misses.

Architecture:
1. At startup: load threat vectors from JSON, embed them, store as numpy matrix
2. At scan time: embed the incoming prompt, cosine-similarity against all threats
3. Return the closest match if above threshold
"""

import json
from pathlib import Path
from typing import Optional

import numpy as np

from models import DetectionLayer, ScanResult, ThreatCategory

# Lazy-load to avoid heavy import at module level
_model = None


def _get_model():
    """Lazy singleton for the sentence-transformer model."""
    global _model
    if _model is None:
        from sentence_transformers import SentenceTransformer
        # all-MiniLM-L6-v2: 384-dim, fast, good for semantic similarity
        _model = SentenceTransformer("all-MiniLM-L6-v2", local_files_only=True)
    return _model


class ThreatVector:
    """A single known threat pattern with its embedding."""
    __slots__ = ("id", "text", "category", "embedding")

    def __init__(self, id: str, text: str, category: str, embedding: np.ndarray):
        self.id = id
        self.text = text
        self.category = ThreatCategory(category)
        self.embedding = embedding


class SemanticDetector:
    """
    Compares incoming prompts against a store of known adversarial
    prompt embeddings using cosine similarity.
    """

    def __init__(
        self,
        threat_store_path: str = "./data/threats/threat_vectors.json",
        threshold: float = 0.70,
    ):
        self.threshold = threshold
        self.threats: list[ThreatVector] = []
        self.threat_matrix: Optional[np.ndarray] = None  # shape: (N, 384)
        self.load_error: Optional[str] = None
        try:
            self._load_threat_store(Path(threat_store_path))
        except Exception as exc:
            self.load_error = str(exc)
            self.threats = []
            self.threat_matrix = None

    def _load_threat_store(self, path: Path) -> None:
        """Load threat texts, embed them, build the comparison matrix."""
        if not path.exists():
            print(f"[SemanticDetector] Threat store not found: {path}")
            return

        with open(path) as f:
            data = json.load(f)

        threat_texts = []
        threat_metadata = []

        for t in data.get("threats", []):
            threat_texts.append(t["text"])
            threat_metadata.append({"id": t["id"], "category": t["category"]})

        if not threat_texts:
            return

        model = _get_model()
        embeddings = model.encode(threat_texts, normalize_embeddings=True, show_progress_bar=False)

        for i, emb in enumerate(embeddings):
            self.threats.append(ThreatVector(
                id=threat_metadata[i]["id"],
                text=threat_texts[i],
                category=threat_metadata[i]["category"],
                embedding=emb,
            ))

        # Stack into matrix for vectorized cosine similarity
        self.threat_matrix = np.stack([t.embedding for t in self.threats])

    def scan(self, prompt: str) -> ScanResult:
        """
        Embed the prompt, compare against all threat vectors.
        Returns the closest match if above threshold.
        """
        if self.threat_matrix is None or len(self.threats) == 0:
            details = {}
            if self.load_error:
                details["load_error"] = self.load_error
            return ScanResult(
                layer=DetectionLayer.SEMANTIC_SIMILARITY,
                triggered=False,
                details=details,
            )

        model = _get_model()
        prompt_embedding = model.encode(
            [prompt], normalize_embeddings=True, show_progress_bar=False
        )[0]

        # Cosine similarity (embeddings are L2-normalized, so dot product = cosine sim)
        similarities = self.threat_matrix @ prompt_embedding

        top_idx = int(np.argmax(similarities))
        top_score = float(similarities[top_idx])

        # Get top 3 matches for audit context
        top_k_indices = np.argsort(similarities)[-3:][::-1]
        top_matches = [
            {
                "threat_id": self.threats[i].id,
                "category": self.threats[i].category.value,
                "similarity": round(float(similarities[i]), 4),
                "threat_text": self.threats[i].text[:80] + "...",
            }
            for i in top_k_indices
        ]

        triggered = top_score >= self.threshold
        closest_threat = self.threats[top_idx]

        return ScanResult(
            layer=DetectionLayer.SEMANTIC_SIMILARITY,
            triggered=triggered,
            category=closest_threat.category if triggered else ThreatCategory.CLEAN,
            confidence=round(top_score, 4),
            matched_pattern=closest_threat.text[:100] if triggered else None,
            details={
                "top_similarity": round(top_score, 4),
                "closest_threat_id": closest_threat.id,
                "top_matches": top_matches,
                "threshold": self.threshold,
            },
        )

    @property
    def threat_count(self) -> int:
        return len(self.threats)
