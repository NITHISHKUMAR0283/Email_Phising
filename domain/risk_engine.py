"""
risk_engine.py — Unified Risk Scoring Engine
=============================================

Aggregates risk signals from multiple detection modules into a single
composite **Severity Grade**.

Detection Layers
-----------------
1. **NLP**        – Content / text-based analysis  (``nlp_score``)
2. **Link**       – URL / domain reputation         (``link_score``)
3. **Header**     – Authentication & routing checks  (``header_score``)
4. **Visual**     – Logo / brand impersonation        (``visual_score``)

Each sub-score is expected to be a float in [0.0, 1.0].

Author : Phishing Detection Team
License: MIT
"""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict, field
from typing import Any, Dict, Optional


# ════════════════════════════════════════════════════════════════════
# Severity grades
# ════════════════════════════════════════════════════════════════════

SEVERITY_LABELS = {
    "CRITICAL": {"min": 0.80, "emoji": "🔴", "color": "#e74c3c"},
    "HIGH":     {"min": 0.60, "emoji": "🟠", "color": "#f39c12"},
    "MEDIUM":   {"min": 0.40, "emoji": "🟡", "color": "#f1c40f"},
    "LOW":      {"min": 0.20, "emoji": "🟢", "color": "#2ecc71"},
    "SAFE":     {"min": 0.00, "emoji": "✅", "color": "#27ae60"},
}


def severity_label(score: float) -> str:
    """Map a [0, 1] score to a human-readable severity label.

    Args:
        score: Composite risk score.

    Returns:
        One of ``'CRITICAL'``, ``'HIGH'``, ``'MEDIUM'``, ``'LOW'``, ``'SAFE'``.
    """
    for label, meta in SEVERITY_LABELS.items():
        if score >= meta["min"]:
            return label
    return "SAFE"


# ════════════════════════════════════════════════════════════════════
# Risk aggregation
# ════════════════════════════════════════════════════════════════════

@dataclass
class RiskReport:
    """Final risk report combining all detection layers."""

    nlp_score: float = 0.0
    link_score: float = 0.0
    header_score: float = 0.0
    visual_score: float = 0.0

    composite_score: float = 0.0
    severity: str = "SAFE"
    confidence: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self, **kw: Any) -> str:
        kw.setdefault("indent", 2)
        return json.dumps(self.to_dict(), **kw)


# Default weights — tweak via ``compute_risk(..., weights=...)``.
DEFAULT_WEIGHTS: Dict[str, float] = {
    "nlp":    0.35,
    "link":   0.25,
    "header": 0.30,
    "visual": 0.10,
}


def compute_risk(
    *,
    nlp_score: float = 0.0,
    link_score: float = 0.0,
    header_score: float = 0.0,
    visual_score: float = 0.0,
    weights: Optional[Dict[str, float]] = None,
    details: Optional[Dict[str, Any]] = None,
) -> RiskReport:
    """Combine sub-module scores into a single severity grade.

    Uses a weighted average.  The *weights* dict should map
    ``'nlp'``, ``'link'``, ``'header'``, ``'visual'`` to float
    weights (they will be normalised automatically).

    Args:
        nlp_score:    NLP / content analysis risk score  [0–1].
        link_score:   URL / link analysis risk score     [0–1].
        header_score: Header analysis risk score         [0–1].
        visual_score: Visual / logo analysis risk score  [0–1].
        weights:      Override default weight distribution.
        details:      Optional metadata to attach.

    Returns:
        A :class:`RiskReport` instance.
    """
    w = weights or DEFAULT_WEIGHTS
    total_weight = sum(w.values()) or 1.0

    composite = (
        w.get("nlp", 0) * nlp_score
        + w.get("link", 0) * link_score
        + w.get("header", 0) * header_score
        + w.get("visual", 0) * visual_score
    ) / total_weight

    composite = round(min(max(composite, 0.0), 1.0), 4)

    # Confidence heuristic: how much sub-score agreement exists.
    scores = [nlp_score, link_score, header_score, visual_score]
    active = [s for s in scores if s > 0]
    if active:
        mean = sum(active) / len(active)
        variance = sum((s - mean) ** 2 for s in active) / len(active)
        confidence = round(1.0 - min(variance, 1.0), 2)
    else:
        confidence = 0.0

    return RiskReport(
        nlp_score=nlp_score,
        link_score=link_score,
        header_score=header_score,
        visual_score=visual_score,
        composite_score=composite,
        severity=severity_label(composite),
        confidence=confidence,
        details=details or {},
    )


# ════════════════════════════════════════════════════════════════════
# Integration helper — convenience wrapper
# ════════════════════════════════════════════════════════════════════

def quick_assess(
    raw_email: str,
    *,
    nlp_score: float = 0.0,
    link_score: float = 0.0,
    visual_score: float = 0.0,
    perform_rdns: bool = False,
) -> RiskReport:
    """One-call risk assessment: runs header analysis internally and
    merges with externally-provided sub-scores.

    Args:
        raw_email: Raw RFC 822 email string.
        nlp_score: Pre-computed NLP risk score.
        link_score: Pre-computed link risk score.
        visual_score: Pre-computed visual risk score.
        perform_rdns: Forward to :func:`header_analyzer.analyze_headers`.

    Returns:
        A :class:`RiskReport`.
    """
    from header_analyzer import analyze_headers

    header_result = analyze_headers(raw_email, perform_rdns=perform_rdns)

    return compute_risk(
        nlp_score=nlp_score,
        link_score=link_score,
        header_score=header_result.header_risk_score,
        visual_score=visual_score,
        details={"header_analysis": header_result.to_dict()},
    )


# ════════════════════════════════════════════════════════════════════
# Demo
# ════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # Simulate sub-scores from other modules
    report = compute_risk(
        nlp_score=0.72,
        link_score=0.85,
        header_score=0.90,
        visual_score=0.0,
    )
    print(report.to_json())
    meta = SEVERITY_LABELS[report.severity]
    print(f"\n{meta['emoji']}  Severity: {report.severity}  "
          f"(composite={report.composite_score})")
