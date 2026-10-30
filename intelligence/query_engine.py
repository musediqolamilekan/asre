"""
Query Engine — "What part of the codebase matters for this problem?"

Given a natural-language error message, keyword, or module name, this engine:
  1. Scores every file in the repo against the query
  2. Ranks by relevance (keyword match) × risk (score)
  3. Returns an ordered list of FileProfiles with explanations

Matching strategy (multi-signal):
  - File name / path contains keyword               → high signal
  - Function / class name contains keyword          → medium signal
  - Lexical-tier files: internal tokens match query → medium signal
  - File imports something that matches keyword     → low signal
  - File is imported by something that matches      → low signal

Final rank = match_strength * risk_score, normalised 0–100
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from collections import Counter
from math import log
from typing import Iterable

from .file_profile import FileProfile


_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_NON_LOWER_BOUNDARY_RE = re.compile(r"([a-z0-9])([A-Z])")
_ACRONYM_BOUNDARY_RE = re.compile(r"([A-Z]+)([A-Z][a-z])")


def tokenize_identifiers(text: str) -> list[str]:
    """Split CamelCase, snake_case, and plain identifiers into normalized terms."""
    tokens: list[str] = []
    for identifier in _IDENTIFIER_RE.findall(text):
        expanded = _NON_LOWER_BOUNDARY_RE.sub(r"\1 \2", identifier)
        expanded = _ACRONYM_BOUNDARY_RE.sub(r"\1 \2", expanded)
        tokens.extend(part.lower() for part in expanded.replace("_", " ").split() if len(part) > 1)
    return tokens


def build_lexical_relationships(
    documents: dict[str, Iterable[str]],
    max_neighbors: int = 5,
    min_score: float = 0.35,
) -> dict[str, list[tuple[str, float, tuple[str, ...]]]]:
    """Infer file relationships with BM25 over shared identifiers."""
    term_documents: dict[str, Counter[str]] = {
        path: Counter(tokens)
        for path, tokens in documents.items()
    }
    document_count = len(term_documents)
    if document_count < 2:
        return {}

    document_frequency: Counter[str] = Counter()
    for frequencies in term_documents.values():
        document_frequency.update(frequencies.keys())

    average_length = (
        sum(sum(frequencies.values()) for frequencies in term_documents.values()) / document_count
    )
    relationships: dict[str, list[tuple[str, float, tuple[str, ...]]]] = {}

    for source, source_terms in term_documents.items():
        candidates: list[tuple[str, float, tuple[str, ...]]] = []
        source_length = sum(source_terms.values())
        for target, target_terms in term_documents.items():
            if source == target:
                continue
            shared = source_terms.keys() & target_terms.keys()
            if not shared:
                continue

            score = 0.0
            shared_terms: list[str] = []
            target_length = sum(target_terms.values())
            for term in shared:
                frequency = document_frequency[term]
                if frequency <= 1:
                    continue
                inverse_document_frequency = log(
                    1.0 + (document_count - frequency + 0.5) / (frequency + 0.5)
                )
                term_frequency = source_terms[term]
                denominator = term_frequency + 1.2 * (
                    1.0 - 0.75 + 0.75 * source_length / max(average_length, 1.0)
                )
                target_component = target_terms[term] / max(target_length, 1) * 0.25
                score += inverse_document_frequency * (2.2 * term_frequency / denominator) * (1.0 + target_component)
                shared_terms.append(term)

            if score >= min_score:
                candidates.append((target, round(score, 6), tuple(sorted(shared_terms))))

        relationships[source] = sorted(candidates, key=lambda item: (-item[1], item[0]))[:max_neighbors]

    return relationships


@dataclass
class QueryMatch:
    """A single file matched by the query engine."""
    profile: FileProfile
    relevance_score: float          # 0.0 – 1.0
    match_reasons: list[str]        # human-readable explanation of why it matched
    final_score: float              # relevance * risk, normalised

    def to_dict(self) -> dict:
        d = self.profile.to_dict()
        d["query_relevance"] = round(self.relevance_score, 3)
        d["query_final_score"] = round(self.final_score, 1)
        d["match_reasons"] = self.match_reasons
        return d


def _tokenise(text: str) -> set[str]:
    """Split text into lowercase tokens (words + camelCase + snake_case parts)."""
    # Split on non-alphanumeric, plus camelCase and PascalCase boundaries
    raw = re.sub(r'([a-z])([A-Z])', r'\1 \2', text)
    raw = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1 \2', raw)
    parts = re.split(r'[\W_]+', raw)
    return {p.lower() for p in parts if len(p) > 1}


def _token_overlap(query_tokens: set[str], text: str) -> float:
    """
    Returns the fraction of query tokens that appear in text's token set.
    """
    if not query_tokens:
        return 0.0
    text_tokens = _tokenise(text)
    common = query_tokens & text_tokens
    return len(common) / len(query_tokens)


def _substring_in(query_lower: str, candidates: list[str]) -> bool:
    return any(query_lower in s.lower() for s in candidates)


def query_codebase(
    profiles: dict[str, FileProfile],
    query: str,
    top_n: int = 10,
) -> list[QueryMatch]:
    """
    Main entry point — returns top_n most relevant files for the query.
    """
    query_lower = query.lower().strip()
    query_tokens = _tokenise(query)

    results: list[QueryMatch] = []

    for path, profile in profiles.items():
        reasons: list[str] = []
        relevance = 0.0

        # ── Signal 1: file path / name (highest weight) ──────────────
        path_overlap = _token_overlap(query_tokens, path)
        if path_overlap > 0:
            bonus = 0.5 * path_overlap
            relevance += bonus
            reasons.append(f"File path matches ({path_overlap:.0%} of query terms)")

        if query_lower in profile.basename.lower():
            relevance += 0.4
            reasons.append(f"File name contains '{query_lower}'")

        # ── Signal 2: function / class names ──────────────────────────
        fn_texts = " ".join(profile.functions + profile.classes +
                            profile.interfaces + profile.structs)
        sym_overlap = _token_overlap(query_tokens, fn_texts)
        if sym_overlap > 0:
            bonus = 0.35 * sym_overlap
            relevance += bonus
            reasons.append(f"Symbols match ({sym_overlap:.0%} of query terms)")

        if _substring_in(query_lower, profile.functions):
            relevance += 0.3
            reasons.append(f"Function name contains '{query_lower}'")

        if _substring_in(query_lower, profile.classes):
            relevance += 0.25
            reasons.append(f"Class name contains '{query_lower}'")

        # ── Signal 3: lexical tokens (Tier 3 asset / unknown files) ──
        # Structural files already scored symbols above. Lexical files
        # have empty functions/classes/imports, so score their token map.
        if getattr(profile, "analysis_tier", None) == "lexical":
            lexical_terms = getattr(profile, "lexical_terms", None) or {}
            term_tokens = set(lexical_terms)
            if query_tokens and term_tokens:
                common = query_tokens & term_tokens
                if common:
                    overlap = len(common) / len(query_tokens)
                    matched_occurrences = sum(lexical_terms[t] for t in common)
                    total_occurrences = sum(lexical_terms.values()) or 1
                    density = matched_occurrences / total_occurrences
                    bonus = 0.45 * overlap + 0.15 * density
                    relevance += bonus
                    reasons.append(
                        f"Lexical terms match ({overlap:.0%} of query terms)"
                    )

            if query_lower and any(query_lower in term for term in term_tokens):
                relevance += 0.3
                reasons.append(f"Lexical term contains '{query_lower}'")

        # ── Signal 4: import relationships ───────────────────────────
        all_related = profile.imports + profile.imported_by
        if _substring_in(query_lower, all_related):
            relevance += 0.15
            reasons.append("Related through import chain")

        # ── Signal 5: TODO messages ───────────────────────────────────
        todo_texts = " ".join(t.get("message", "") for t in profile.todos)
        if todo_texts and query_lower in todo_texts.lower():
            relevance += 0.1
            reasons.append("Mentioned in TODO/FIXME comment")

        if relevance == 0.0:
            continue

        # Final score = relevance (0–1) × risk normalised weight
        # We boost high-risk files because they are more architecturally important
        risk_weight = 1.0 + (profile.risk_score / 100.0)
        final = min(relevance * risk_weight * 50, 100)

        results.append(QueryMatch(
            profile=profile,
            relevance_score=min(relevance, 1.0),
            match_reasons=reasons,
            final_score=final,
        ))

    # Sort by final score desc, then by risk_score desc as tiebreaker
    results.sort(key=lambda r: (-r.final_score, -r.profile.risk_score))
    return results[:top_n]
