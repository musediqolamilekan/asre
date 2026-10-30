"""
File Profile Engine

Produces a comprehensive per-file profile that answers:
  - "Who uses this file?"           → imported_by tree
  - "What does this file import?"   → imports list
  - "What does it expose?"          → functions, classes, structs
  - "How risky is it?"              → ScoreBreakdown (deterministic, explainable)
  - "What breaks if it breaks?"     → transitive_dependents
  - "How recently was it changed?"  → recent_changes (git)

The profile is the primary data structure exported as JSON or
rendered in the terminal.
"""

from __future__ import annotations
import os
from dataclasses import dataclass, field
from typing import Optional

from .dependency_graph import DependencyGraph
from .models import RepoIntelligence, FileAnalysis
from .risk_scorer import (
    ScoreBreakdown,
    compute_all_breakdowns,
    risk_label,
    risk_icon,
)


@dataclass
class FileProfile:
    """Complete intelligence profile for a single file."""

    # ── Identity ────────────────────────────────────────────────────
    file: str               # repo-relative path
    basename: str           # just the filename
    language: str
    lines: int
    size_bytes: int
    last_modified: str = ""  # ISO date of last git commit

    # ── Dependency relationships ────────────────────────────────────
    imports: list[str]              = field(default_factory=list)
    imported_by: list[str]          = field(default_factory=list)
    transitive_consumers: list[str] = field(default_factory=list)

    # ── Symbols (extracted by Tree-sitter) ──────────────────────────
    functions: list[str]    = field(default_factory=list)
    classes: list[str]      = field(default_factory=list)
    interfaces: list[str]   = field(default_factory=list)
    structs: list[str]      = field(default_factory=list)
    todos: list[dict]       = field(default_factory=list)
    analysis_tier: str      = "unknown"
    lexical_terms: dict[str, int] = field(default_factory=dict)
    parse_errors: list[dict] = field(default_factory=list)
    # ── Risk (deterministic breakdown) ──────────────────────────────
    score_breakdown: Optional[ScoreBreakdown] = None

    # ── Derived convenience fields ──────────────────────────────────
    recent_changes: int     = 0   # git commits in last 90d
    direct_impact: int      = 0   # count of direct importers
    transitive_impact: int  = 0   # count of all downstream consumers
    coupling_score: int     = 0   # how many other files this imports

    # ── Computed from ScoreBreakdown ────────────────────────────────
    @property
    def risk_score(self) -> int:
        return self.score_breakdown.total if self.score_breakdown else 0

    @property
    def risk_label(self) -> str:
        return self.score_breakdown.label if self.score_breakdown else "Low"

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "language": self.language,
            "lines": self.lines,
            "size_bytes": self.size_bytes,
            "last_modified": self.last_modified,
            "imports": self.imports,
            "imported_by": self.imported_by,
            "transitive_consumers": self.transitive_consumers,
            "functions": self.functions,
            "classes": self.classes,
            "interfaces": self.interfaces,
            "structs": self.structs,
            "todos": len(self.todos),
            "analysis_tier": self.analysis_tier,
            "lexical_terms": self.lexical_terms,
            "parse_errors": self.parse_errors,
            "recent_changes": self.recent_changes,
            "risk_score": self.risk_score,
            "risk_label": self.risk_label,
            "score_breakdown": self.score_breakdown.to_dict() if self.score_breakdown else None,
            "direct_impact": self.direct_impact,
            "transitive_impact": self.transitive_impact,
            "coupling_score": self.coupling_score,
        }


def build_file_profiles(
    graph: DependencyGraph,
    intel: RepoIntelligence,
    file_change_counts: Optional[dict[str, int]] = None,
    file_last_modified: Optional[dict[str, str]] = None,
) -> dict[str, FileProfile]:
    """
    Builds a FileProfile for every file in the repo that
    appears in the graph or was analysed by Tree-sitter.

    Args:
        graph:              the dependency graph
        intel:              full repo intelligence scan
        file_change_counts: {path: commit_count} from git_analyzer
        file_last_modified: {path: date_str} from git_analyzer
    """
    file_change_counts = file_change_counts or {}
    file_last_modified = file_last_modified or {}

    fa_map: dict[str, FileAnalysis] = {fa.path: fa for fa in intel.file_analyses}

    # Compute all breakdowns in one pass
    breakdowns = compute_all_breakdowns(graph, intel, file_change_counts)

    profiles: dict[str, FileProfile] = {}
    all_paths = set(graph.all_nodes()) | set(fa_map.keys())

    for path in all_paths:
        fa = fa_map.get(path)
        imports       = graph.dependencies(path)
        imported_by   = graph.dependents(path)
        trans         = graph.transitive_dependents(path)
        breakdown     = breakdowns.get(path)

        # Resolve last_modified: try exact path, then basename match
        last_mod = file_last_modified.get(path, "")
        if not last_mod:
            for k, v in file_last_modified.items():
                if k.endswith(path) or path.endswith(k):
                    last_mod = v
                    break

        # Recent changes count (same path-matching logic as scorer)
        recent = file_change_counts.get(path, 0)
        if recent == 0:
            for k, v in file_change_counts.items():
                if k.endswith(path) or path.endswith(k):
                    recent = v
                    break

        profile = FileProfile(
            file=path,
            basename=os.path.basename(path),
            language=fa.language if fa else "unknown",
            lines=fa.lines if fa else 0,
            size_bytes=fa.size_bytes if fa else 0,
            last_modified=last_mod,
            imports=imports,
            imported_by=imported_by,
            transitive_consumers=trans,
            functions=fa.functions if fa else [],
            classes=fa.classes if fa else [],
            interfaces=fa.interfaces if fa else [],
            structs=fa.structs if fa else [],
            todos=fa.todos if fa else [],
            analysis_tier=fa.analysis_tier if fa else "unknown",
            lexical_terms=fa.lexical_terms if fa else {},
            parse_errors=fa.parse_errors if fa else [],
            score_breakdown=breakdown,
            recent_changes=recent,
            direct_impact=len(imported_by),
            transitive_impact=len(trans),
            coupling_score=len(imports),
        )
        profiles[path] = profile

    return profiles


def get_profile(
    profiles: dict[str, FileProfile],
    query: str,
) -> list[FileProfile]:
    """
    Fuzzy-matches `query` against all profile keys and basenames.
    Returns a sorted list of matching profiles (best match first).
    """
    query_lower = query.lower()
    matches = []

    for path, profile in profiles.items():
        if query_lower in path.lower() or query_lower in profile.basename.lower():
            matches.append(profile)

    def rank(p: FileProfile):
        exact = 0 if p.basename.lower() == query_lower else 1
        return (exact, -p.risk_score)

    return sorted(matches, key=rank)
