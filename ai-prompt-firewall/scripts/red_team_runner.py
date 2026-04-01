"""
Red Team Runner — Automated firewall testing.
=============================================
Runs every attack in the dataset through all detection layers,
compares results against expected outcomes, and generates a
bypass rate report with per-category and per-difficulty breakdowns.

Usage:
    python -m scripts.red_team_runner
"""

import json
import sys
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from engine.rule_engine import RuleEngine
from detection.pii.pii_detector import PIIDetector
from detection.semantic.semantic_detector import SemanticDetector
from models import ScanResult

console = Console()

ATTACK_DATASET = Path("data/attacks/red_team_dataset.json")
REPORT_OUTPUT = Path("data/attacks/red_team_report.json")


def run_scan(
    rule_engine: RuleEngine,
    pii_detector: PIIDetector,
    semantic_detector: SemanticDetector,
    prompt: str,
    threshold: float = 0.70,
) -> dict:
    """Run a single prompt through all layers, return aggregated result."""
    results: list[ScanResult] = [
        rule_engine.scan(prompt),
        pii_detector.scan(prompt),
        semantic_detector.scan(prompt),
    ]

    triggered = any(r.triggered and r.confidence >= threshold for r in results)
    highest = max((r for r in results if r.triggered), key=lambda r: r.confidence, default=None)

    return {
        "triggered": triggered,
        "blocked_by": highest.layer.value if highest and triggered else None,
        "confidence": highest.confidence if highest else 0.0,
        "category": highest.category.value if highest and triggered else "clean",
        "layer_results": [r.model_dump(mode="json") for r in results],
    }


def main():
    console.print(Panel.fit(
        "[bold red]AI Prompt Firewall — Red Team Runner[/bold red]\n"
        "Testing firewall against adversarial attack dataset",
        border_style="red",
    ))

    # Load attack dataset
    with open(ATTACK_DATASET) as f:
        dataset = json.load(f)

    attacks = dataset["attacks"]
    console.print(f"\nLoaded [bold]{len(attacks)}[/bold] test cases\n")

    # Initialize detection layers
    console.print("[dim]Initializing detection layers...[/dim]")
    rule_engine = RuleEngine(rules_dir="./engine/rules")
    pii_detector = PIIDetector()
    semantic_detector = SemanticDetector(
        threat_store_path="./data/threats/threat_vectors.json",
        threshold=0.70,
    )
    console.print(
        f"  Rules loaded: {rule_engine.rule_count} | "
        f"Threat vectors: {semantic_detector.threat_count}\n"
    )

    # Run all attacks
    results = []
    tp, fp, tn, fn = 0, 0, 0, 0

    for attack in attacks:
        scan = run_scan(rule_engine, pii_detector, semantic_detector, attack["prompt"])

        expected_block = attack["should_block"]
        actual_block = scan["triggered"]
        correct = expected_block == actual_block

        if expected_block and actual_block:
            tp += 1
        elif not expected_block and not actual_block:
            tn += 1
        elif not expected_block and actual_block:
            fp += 1
        else:
            fn += 1

        results.append({
            "id": attack["id"],
            "prompt": attack["prompt"][:80] + "...",
            "expected_category": attack["expected_category"],
            "expected_block": expected_block,
            "actual_block": actual_block,
            "actual_category": scan["category"],
            "blocked_by": scan["blocked_by"],
            "confidence": scan["confidence"],
            "correct": correct,
            "difficulty": attack.get("difficulty", "unknown"),
        })

    # ── Results Table ─────────────────────────────────────────
    table = Table(title="Red Team Results", show_lines=True)
    table.add_column("ID", style="dim", width=8)
    table.add_column("Expected", width=10)
    table.add_column("Actual", width=10)
    table.add_column("Layer", width=12)
    table.add_column("Conf", width=6)
    table.add_column("Result", width=8)
    table.add_column("Difficulty", width=8)

    for r in results:
        result_style = "green" if r["correct"] else "bold red"
        result_text = "✓ PASS" if r["correct"] else "✗ FAIL"
        table.add_row(
            r["id"],
            "BLOCK" if r["expected_block"] else "ALLOW",
            "BLOCK" if r["actual_block"] else "ALLOW",
            r["blocked_by"] or "—",
            f"{r['confidence']:.2f}",
            f"[{result_style}]{result_text}[/{result_style}]",
            r["difficulty"],
        )

    console.print(table)

    # ── Metrics ───────────────────────────────────────────────
    total = len(results)
    accuracy = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    bypass_rate = fn / (tp + fn) if (tp + fn) > 0 else 0

    # Per-difficulty breakdown
    difficulty_stats = {}
    for r in results:
        d = r["difficulty"]
        if d not in difficulty_stats:
            difficulty_stats[d] = {"total": 0, "correct": 0, "bypassed": 0}
        difficulty_stats[d]["total"] += 1
        if r["correct"]:
            difficulty_stats[d]["correct"] += 1
        if r["expected_block"] and not r["actual_block"]:
            difficulty_stats[d]["bypassed"] += 1

    # Per-category breakdown
    category_stats = {}
    for r in results:
        c = r["expected_category"]
        if c not in category_stats:
            category_stats[c] = {"total": 0, "correct": 0, "bypassed": 0}
        category_stats[c]["total"] += 1
        if r["correct"]:
            category_stats[c]["correct"] += 1
        if r["expected_block"] and not r["actual_block"]:
            category_stats[c]["bypassed"] += 1

    metrics_table = Table(title="Detection Metrics", show_lines=True)
    metrics_table.add_column("Metric", style="bold")
    metrics_table.add_column("Value", justify="right")
    metrics_table.add_row("True Positives", str(tp))
    metrics_table.add_row("True Negatives", str(tn))
    metrics_table.add_row("False Positives", str(fp))
    metrics_table.add_row("False Negatives (Bypasses)", f"[red]{fn}[/red]")
    metrics_table.add_row("Accuracy", f"{accuracy:.2%}")
    metrics_table.add_row("Precision", f"{precision:.2%}")
    metrics_table.add_row("Recall (Detection Rate)", f"{recall:.2%}")
    metrics_table.add_row("F1 Score", f"{f1:.2%}")
    metrics_table.add_row("[bold red]Bypass Rate[/bold red]", f"[bold red]{bypass_rate:.2%}[/bold red]")
    console.print(metrics_table)

    # Difficulty breakdown
    diff_table = Table(title="By Difficulty", show_lines=True)
    diff_table.add_column("Difficulty")
    diff_table.add_column("Total", justify="right")
    diff_table.add_column("Correct", justify="right")
    diff_table.add_column("Bypassed", justify="right")
    for d, s in sorted(difficulty_stats.items()):
        diff_table.add_row(d, str(s["total"]), str(s["correct"]), str(s["bypassed"]))
    console.print(diff_table)

    # Category breakdown
    cat_table = Table(title="By Category", show_lines=True)
    cat_table.add_column("Category")
    cat_table.add_column("Total", justify="right")
    cat_table.add_column("Correct", justify="right")
    cat_table.add_column("Bypassed", justify="right")
    for c, s in sorted(category_stats.items()):
        cat_table.add_row(c, str(s["total"]), str(s["correct"]), str(s["bypassed"]))
    console.print(cat_table)

    # ── Save report ───────────────────────────────────────────
    report = {
        "timestamp": datetime.now().isoformat(),
        "total_tests": total,
        "metrics": {
            "tp": tp, "tn": tn, "fp": fp, "fn": fn,
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "bypass_rate": round(bypass_rate, 4),
        },
        "difficulty_breakdown": difficulty_stats,
        "category_breakdown": category_stats,
        "detailed_results": results,
    }

    REPORT_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(REPORT_OUTPUT, "w") as f:
        json.dump(report, f, indent=2)

    console.print(f"\n[green]Report saved to {REPORT_OUTPUT}[/green]")


if __name__ == "__main__":
    main()
