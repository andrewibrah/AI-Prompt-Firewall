"""
Rule Engine — YAML-based pattern matching for known attack signatures.
=====================================================================
- Loads all .yaml files from rules directory at startup
- Compiles regex patterns once for performance
- Returns ScanResult with highest-severity match
"""

import re
from pathlib import Path
from typing import Optional

import yaml

from models import DetectionLayer, ScanResult, ThreatCategory


class CompiledRule:
    """A single compiled detection rule."""

    __slots__ = ("id", "name", "pattern", "compiled", "category", "severity", "description")

    def __init__(self, data: dict):
        self.id: str = data["id"]
        self.name: str = data["name"]
        self.pattern: str = data["pattern"]
        self.compiled: re.Pattern = re.compile(data["pattern"], re.IGNORECASE | re.DOTALL)
        self.category: ThreatCategory = ThreatCategory(data["category"])
        self.severity: float = float(data["severity"])
        self.description: str = data.get("description", "")


class RuleEngine:
    """
    Loads YAML rule files, compiles them, and scans prompts.
    Returns the highest-severity match found.
    """

    def __init__(self, rules_dir: str = "./engine/rules"):
        self.rules: list[CompiledRule] = []
        self._load_rules(Path(rules_dir))

    def _load_rules(self, rules_dir: Path) -> None:
        """Load and compile all YAML rule files."""
        if not rules_dir.exists():
            return
        for yaml_file in sorted(rules_dir.glob("*.yaml")):
            with open(yaml_file) as f:
                data = yaml.safe_load(f)
            if not data or "rules" not in data:
                continue
            for rule_data in data["rules"]:
                try:
                    self.rules.append(CompiledRule(rule_data))
                except (re.error, KeyError, ValueError) as e:
                    print(f"[RuleEngine] Skipping bad rule {rule_data.get('id', '?')}: {e}")

    def scan(self, prompt: str) -> ScanResult:
        """
        Scan a prompt against all compiled rules.
        Returns the highest-severity match.
        """
        best_match: Optional[CompiledRule] = None
        best_severity: float = 0.0
        all_matches: list[dict] = []

        for rule in self.rules:
            match = rule.compiled.search(prompt)
            if match:
                all_matches.append({
                    "rule_id": rule.id,
                    "rule_name": rule.name,
                    "severity": rule.severity,
                    "matched_text": match.group()[:100],
                })
                if rule.severity > best_severity:
                    best_severity = rule.severity
                    best_match = rule

        if best_match:
            return ScanResult(
                layer=DetectionLayer.RULE_ENGINE,
                triggered=True,
                category=best_match.category,
                confidence=best_match.severity,
                matched_pattern=best_match.pattern,
                details={
                    "rule_id": best_match.id,
                    "rule_name": best_match.name,
                    "total_matches": len(all_matches),
                    "all_matches": all_matches,
                },
            )

        return ScanResult(
            layer=DetectionLayer.RULE_ENGINE,
            triggered=False,
        )

    @property
    def rule_count(self) -> int:
        return len(self.rules)
