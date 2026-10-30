"""
Risk Scorer  —  Deterministic, Reproducible, Explainable

Every score is the **exact sum** of named components with fixed weights and caps.
No fuzzy math. No magic constants hidden inside formulas.

Score Formula
─────────────────────────────────────────────────────────────────────
COMPONENT              WEIGHT   CAP   DATA SOURCE
─────────────────────────────────────────────────────────────────────
direct_dependents      ×  5     25    graph.dependents()
transitive_dependents  ×  2     30    graph.transitive_dependents() (BFS)
recent_changes (90d)   ×  3     15    git log --follow (last 90 days)
public_symbols         ×  1     20    tree-sitter functions + classes
─────────────────────────────────────────────────────────────────────
Max total                        90   (raw, not normalized)

Risk Labels
─────────────────────────────────────────────────────────────────────
≥ 65 → Critical    (touches core of many systems)
≥ 40 → High        (high coupling or high churn)
≥ 20 → Medium      (moderate coupling)
<  20 → Low        (isolated or rarely-used)

Reproducibility guarantee:
  Given the same repo state and the same git history window, this
  function ALWAYS produces the same score for the same file.
  The only non-deterministic input is wall-clock time (which commits
  fall within the last 90 days), which is documented explicitly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ── Score weights & caps (change here to update the whole system) ──────────────

COMPONENTS_SPEC = [
    # (key, display_name, description, data_source, weight, cap)
    (
        "direct_dependents",
        "Direct dependents",
        "Files that directly import this file",
        "graph.dependents()",
        5,
        25,
    ),
    (
        "transitive_dependents",
        "Transitive dependents",
        "All downstream consumers (BFS on reverse graph)",
        "graph.transitive_dependents()",
        2,
        30,
    ),
    (
        "recent_changes",
        "Recent changes (90d)",
        "Git commits touching this file in the last 90 days",
        "git log (last 90 days)",
        3,
        15,
    ),
    (
        "public_symbols",
        "Public symbols",
        "Exported functions + classes (public API surface area)",
        "tree-sitter AST extraction",
        1,
        20,
    ),
]

# Thresholds for risk labels
CRITICAL_THRESHOLD = 65
HIGH_THRESHOLD     = 40
MEDIUM_THRESHOLD   = 20


@dataclass
class ScoreComponent:
    """
    One named, traceable component of the risk score.

    All fields are set at construction time and never mutated —
    making the breakdown fully serialisable and deterministic.
    """
    key: str                  # machine identifier
    name: str                 # human display name
    description: str          # what this measures
    data_source: str          # where the raw_value comes from
    raw_value: int            # the actual count from repo data
    weight: int               # points per unit
    cap: int                  # maximum contribution
    points: int               # min(raw_value × weight, cap)  ← always this formula

    @classmethod
    def compute(
        cls,
        key: str,
        name: str,
        description: str,
        data_source: str,
        raw_value: int,
        weight: int,
        cap: int,
    ) -> "ScoreComponent":
        points = min(raw_value * weight, cap)
        return cls(
            key=key,
            name=name,
            description=description,
            data_source=data_source,
            raw_value=raw_value,
            weight=weight,
            cap=cap,
            points=points,
        )

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "name": self.name,
            "raw_value": self.raw_value,
            "weight": self.weight,
            "cap": self.cap,
            "points": self.points,
            "data_source": self.data_source,
        }


@dataclass
class ScoreBreakdown:
    """
    The full, explainable risk score for one file.

    total = sum(c.points for c in components)
    label = derived from total using fixed thresholds

    The breakdown is the canonical answer to: "Why is this file high-risk?"
    """
    file: str
    components: list[ScoreComponent]
    total: int                  # exact sum of component points
    label: str                  # Critical / High / Medium / Low
    max_possible: int           # sum of all caps

    def why(self) -> str:
        """
        Returns a concise human-readable explanation of the score.
        Suitable for displaying to a developer who asks 'Why is this risky?'
        """
        lines = [f"Risk score for '{self.file}': {self.total}/{self.max_possible} ({self.label})\n"]

        for c in self.components:
            if c.points > 0:
                pct = round(c.points / self.max_possible * 100)
                lines.append(
                    f"  • {c.name}: {c.raw_value} × {c.weight} = +{c.points} pts  "
                    f"({pct}% of max)  [{c.data_source}]"
                )

        zero = [c for c in self.components if c.points == 0]
        if zero:
            names = ", ".join(c.name for c in zero)
            lines.append(f"\n  (No contribution from: {names})")

        lines.append(
            f"\nThresholds: Critical ≥{CRITICAL_THRESHOLD}, High ≥{HIGH_THRESHOLD}, "
            f"Medium ≥{MEDIUM_THRESHOLD}, Low <{MEDIUM_THRESHOLD}"
        )
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "total": self.total,
            "max_possible": self.max_possible,
            "label": self.label,
            "components": [c.to_dict() for c in self.components],
        }


def risk_label(score: int) -> str:
    if score >= CRITICAL_THRESHOLD:
        return "Critical"
    if score >= HIGH_THRESHOLD:
        return "High"
    if score >= MEDIUM_THRESHOLD:
        return "Medium"
    return "Low"


def risk_color_code(score: int) -> str:
    if score >= CRITICAL_THRESHOLD:
        return "\033[91m"   # red
    if score >= HIGH_THRESHOLD:
        return "\033[93m"   # yellow / orange
    if score >= MEDIUM_THRESHOLD:
        return "\033[94m"   # blue
    return "\033[92m"       # green


def risk_icon(score: int) -> str:
    if score >= CRITICAL_THRESHOLD:
        return "🔴"
    if score >= HIGH_THRESHOLD:
        return "🟠"
    if score >= MEDIUM_THRESHOLD:
        return "🟡"
    return "🟢"


def compute_score_breakdown(
    path: str,
    direct_dep_count: int,
    transitive_dep_count: int,
    recent_change_count: int,
    public_symbol_count: int,
) -> ScoreBreakdown:
    """
    Computes a fully explainable ScoreBreakdown for a single file.

    All inputs are plain integers — fully deterministic given the same repo state.

    Args:
        path:                 repo-relative file path (for display)
        direct_dep_count:     number of files that directly import this file
        transitive_dep_count: number of all downstream consumers
        recent_change_count:  number of commits touching this file (last 90d)
        public_symbol_count:  number of exported functions + classes
    """
    raw_values = {
        "direct_dependents":     direct_dep_count,
        "transitive_dependents": transitive_dep_count,
        "recent_changes":        recent_change_count,
        "public_symbols":        public_symbol_count,
    }

    spec_map = {s[0]: s for s in COMPONENTS_SPEC}
    components: list[ScoreComponent] = []

    for key, (_, name, desc, source, weight, cap) in spec_map.items():
        raw = raw_values.get(key, 0)
        components.append(ScoreComponent.compute(
            key=key,
            name=name,
            description=desc,
            data_source=source,
            raw_value=raw,
            weight=weight,
            cap=cap,
        ))

    total = sum(c.points for c in components)
    max_possible = sum(cap for _, _, _, _, _, cap in COMPONENTS_SPEC)

    return ScoreBreakdown(
        file=path,
        components=components,
        total=total,
        label=risk_label(total),
        max_possible=max_possible,
    )


def compute_all_breakdowns(
    graph,                          # DependencyGraph
    intel,                          # RepoIntelligence
    file_change_counts: dict[str, int],
) -> dict[str, ScoreBreakdown]:
    """
    Computes ScoreBreakdown for every file in the graph+intel.

    file_change_counts: output of git_analyzer.get_file_change_counts()
    Maps repo-relative paths → number of recent commits.
    """
    from .models import FileAnalysis

    fa_map: dict[str, FileAnalysis] = {fa.path: fa for fa in intel.file_analyses}
    all_paths = set(graph.all_nodes()) | set(fa_map.keys())

    breakdowns: dict[str, ScoreBreakdown] = {}

    for path in all_paths:
        fa = fa_map.get(path)

        direct_deps     = len(graph.dependents(path))
        transitive_deps = len(graph.transitive_dependents(path))

        # git change count: try both the canonical path and just the basename
        recent = file_change_counts.get(path, 0)
        if recent == 0:
            # git may store paths differently; try stripping leading repo name
            for k, v in file_change_counts.items():
                if k.endswith(path) or path.endswith(k):
                    recent = v
                    break

        fns  = len(fa.functions) if fa else 0
        cls  = len(fa.classes)   if fa else 0
        iface = len(fa.interfaces) if fa else 0
        symbols = fns + cls + iface

        breakdowns[path] = compute_score_breakdown(
            path=path,
            direct_dep_count=direct_deps,
            transitive_dep_count=transitive_deps,
            recent_change_count=recent,
            public_symbol_count=symbols,
        )

    return breakdowns
