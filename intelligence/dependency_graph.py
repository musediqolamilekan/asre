"""
Dependency Graph Engine

Builds a directed graph of file-level dependencies, then answers:
  - What does file A depend on?        (dependencies)
  - What files depend on A?            (dependents)
  - If A breaks, what is affected?     (transitive_impact)
  - Which files are most critical?     (impact_scores)
"""

from __future__ import annotations

import os
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional

from .models import EcosystemContext, RepoIntelligence, FileAnalysis
from .resolver import resolve_imports_detailed


# ── Risk Thresholds ────────────────────────────────────────────────────────────
RISK_HIGH   = 10   # directly or transitively used by ≥10 files
RISK_MEDIUM =  4   # used by ≥4 files
# below RISK_MEDIUM → Low


@dataclass
class NodeInfo:
    """Metadata for a single node (file) in the graph."""
    path: str
    language: str
    lines: int
    direct_dependencies: list[str] = field(default_factory=list)   # edges OUT (imports)
    direct_dependents: list[str]   = field(default_factory=list)   # edges IN  (imported-by)
    transitive_dependents: list[str] = field(default_factory=list) # all downstream consumers
    impact_score: int = 0
    risk_level: str = "Low"


@dataclass
class ImpactReport:
    """Result of an impact query: "what breaks if X is broken?" """
    target: str
    language: str
    direct_imports: list[str]          # what target imports
    direct_dependents: list[str]       # who directly imports target
    transitive_dependents: list[str]   # all downstream consumers
    impact_score: int
    risk_level: str
    affected_summary: list[str]        # human-readable list of affected systems
    unresolved_imports: list[str] = field(default_factory=list)
    dependency_data_complete: bool = True


class DependencyGraph:
    """
    Directed graph where edge A→B means "A imports B" (A depends on B).
    The REVERSE direction: B←A means "B is imported by A" (B affects A).
    """

    def __init__(self):
        # Forward edges:  file → set of files it imports
        self._deps:  dict[str, set[str]] = defaultdict(set)
        # Reverse edges: file → set of files that import it
        self._rdeps: dict[str, set[str]] = defaultdict(set)
        # Node metadata
        self._nodes: dict[str, NodeInfo] = {}
        # Keep imports that could not be mapped visible to downstream callers.
        self._import_resolutions: dict[str, list[dict]] = defaultdict(list)
        self._lexical_relationships: dict[str, dict[str, tuple[float, tuple[str, ...]]]] = {}

    # ── Build ──────────────────────────────────────────────────────────────────

    def add_node(self, path: str, language: str, lines: int):
        if path not in self._nodes:
            self._nodes[path] = NodeInfo(path=path, language=language, lines=lines)

    def add_edge(self, source: str, target: str):
        """source imports target."""
        if source == target:
            return
        self._deps[source].add(target)
        self._rdeps[target].add(source)

    # ── Query ──────────────────────────────────────────────────────────────────

    def dependencies(self, path: str) -> list[str]:
        """Files that `path` imports (direct only)."""
        return sorted(self._deps.get(path, set()))

    def dependents(self, path: str) -> list[str]:
        """Files that directly import `path`."""
        return sorted(self._rdeps.get(path, set()))

    def transitive_dependents(self, path: str) -> list[str]:
        """All files transitively affected if `path` breaks (BFS on reverse graph)."""
        visited: set[str] = set()
        queue = deque(self._rdeps.get(path, set()))
        while queue:
            node = queue.popleft()
            if node in visited:
                continue
            visited.add(node)
            queue.extend(self._rdeps.get(node, set()) - visited)
        return sorted(visited)

    def impact_score(self, path: str) -> int:
        return len(self.transitive_dependents(path))

    def risk_level(self, path: str) -> str:
        score = self.impact_score(path)
        if score >= RISK_HIGH:
            return "High"
        elif score >= RISK_MEDIUM:
            return "Medium"
        return "Low"

    def all_nodes(self) -> list[str]:
        return sorted(self._nodes.keys())

    def lexical_relationships(self, path: str) -> list[tuple[str, float, tuple[str, ...]]]:
        relationships = self._lexical_relationships.get(path, {})
        return [
            (target, score, terms)
            for target, (score, terms) in sorted(relationships.items())
        ]

    def lexical_dependents(self, path: str) -> list[str]:
        return sorted(
            source
            for source, relationships in self._lexical_relationships.items()
            if path in relationships
        )

    def import_resolutions(self, path: str) -> list[dict]:
        """Return resolution outcomes, including unresolved imports, for a file."""
        return list(self._import_resolutions.get(path, []))

    def dependency_data_complete(self, path: Optional[str] = None) -> bool:
        """Whether resolution produced no unresolved or ambiguous imports."""
        rows = (self._import_resolutions.get(path, []) if path is not None
                else (row for group in self._import_resolutions.values() for row in group))
        return not any(row["status"] in {"unresolved", "ambiguous"} for row in rows)

    def node_info(self, path: str) -> Optional[NodeInfo]:
        return self._nodes.get(path)

    def most_critical(self, top_n: int = 20) -> list[tuple[str, int, str]]:
        """Returns (path, impact_score, risk_level) sorted by score descending."""
        results = []
        for path in self._nodes:
            score = self.impact_score(path)
            if score > 0:
                results.append((path, score, self.risk_level(path)))
        return sorted(results, key=lambda x: x[1], reverse=True)[:top_n]

    def get_impact_report(self, path: str) -> ImpactReport:
        """Full impact analysis for a single file."""
        direct_deps   = self.dependencies(path)
        direct_deps_on = self.dependents(path)
        trans_deps    = self.transitive_dependents(path)
        score         = len(trans_deps)
        risk          = self.risk_level(path)

        # Summarise affected "systems" by grouping top-level directories
        systems: dict[str, int] = {}
        for dep in trans_deps:
            top = dep.split(os.sep)[0] if os.sep in dep else dep
            systems[top] = systems.get(top, 0) + 1

        affected_summary = [
            f"{top}/ ({cnt} file{'s' if cnt > 1 else ''})"
            for top, cnt in sorted(systems.items(), key=lambda x: x[1], reverse=True)
        ]

        lang = self._nodes[path].language if path in self._nodes else "unknown"
        return ImpactReport(
            target=path,
            language=lang,
            direct_imports=direct_deps,
            direct_dependents=direct_deps_on,
            transitive_dependents=trans_deps,
            impact_score=score,
            risk_level=risk,
            affected_summary=affected_summary,
            unresolved_imports=[r["specifier"] for r in self._import_resolutions.get(path, [])
                                if r["status"] in {"unresolved", "ambiguous"}],
            dependency_data_complete=self.dependency_data_complete(),
        )

    # ── Stats ─────────────────────────────────────────────────────────────────

    def stats(self) -> dict:
        scores = [self.impact_score(p) for p in self._nodes]
        return {
            "total_nodes": len(self._nodes),
            "total_edges": sum(len(v) for v in self._deps.values()),
            "isolated_nodes": sum(1 for p in self._nodes
                                  if not self._deps.get(p) and not self._rdeps.get(p)),
            "unresolved_imports": sum(1 for rows in self._import_resolutions.values()
                                      for row in rows if row["status"] in {"unresolved", "ambiguous"}),
            "dependency_data_complete": self.dependency_data_complete(),
            "max_impact_score": max(scores) if scores else 0,
            "avg_impact_score": round(sum(scores) / len(scores), 2) if scores else 0,
        }


# ── Builder ───────────────────────────────────────────────────────────────────

def build_dependency_graph(intel: RepoIntelligence) -> DependencyGraph:
    """
    Constructs a DependencyGraph from a RepoIntelligence scan result.

    For each file, we take the raw import text already extracted by
    Tree-sitter and pass it through the language-specific resolver to
    find which other files in the repo it actually imports.
    """
    graph = DependencyGraph()

    # Build a fast lookup set of all repo-relative paths
    all_file_set: set[str] = {fa.path for fa in intel.file_analyses}
    repo_root = intel.repo_path

    # Register all nodes first
    for fa in intel.file_analyses:
        graph.add_node(fa.path, fa.language, fa.lines)

    # Now resolve imports and add edges
    for fa in intel.file_analyses:
        if not fa.imports:
            continue

        # The imports list contains full import statement text (from Tree-sitter)
        raw_import_text = "\n".join(fa.imports)

        resolutions = resolve_imports_detailed(
            language=fa.language,
            raw_import_text=raw_import_text,
            current_file=fa.path,
            all_files=all_file_set,
            repo_root=repo_root,
            ecosystem_context=intel.ecosystem_context or EcosystemContext(),
        )

        for outcome in resolutions:
            graph._import_resolutions[fa.path].append({
                "specifier": outcome.specifier,
                "status": outcome.status,
                "paths": list(outcome.paths),
                "reason": outcome.reason,
            })
            for target in outcome.paths:
                graph.add_edge(fa.path, target)

    lexical_documents = {
        fa.path: (term for term, count in fa.lexical_terms.items() for _ in range(count))
        for fa in intel.file_analyses
        if fa.analysis_tier == "lexical"
    }
    if lexical_documents:
        from .query_engine import build_lexical_relationships

        graph._lexical_relationships = {
            source: {
                target: (score, terms)
                for target, score, terms in relationships
            }
            for source, relationships in build_lexical_relationships(lexical_documents).items()
            if relationships
        }

    return graph
