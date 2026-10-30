"""Deterministic conversion of production incidents into repair context."""

from __future__ import annotations

import json
import os
import re
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from intelligence.dependency_graph import DependencyGraph
from intelligence.file_profile import FileProfile
from intelligence.models import EXTENSION_TO_LANGUAGE
from intelligence.query_engine import query_codebase


_NON_TRACEBACK_LANGUAGES = frozenset({"json", "yaml", "toml", "html", "css"})
_TRACEBACK_EXTENSIONS = tuple(
    sorted(
        {
            ext.lstrip(".")
            for ext, language in EXTENSION_TO_LANGUAGE.items()
            if language not in _NON_TRACEBACK_LANGUAGES
        }
        | {"mjs", "cjs", "kts", "hxx"},
        key=len,
        reverse=True,
    )
)
_EXT_GROUP = "|".join(re.escape(ext) for ext in _TRACEBACK_EXTENSIONS)
_PATH_PREFIX = (
    r"(?:file://[^\r\n:\"'`]+|"
    r"(?:[A-Za-z]:[\\/]|/|\.{1,2}[\\/]|[^\s\\/:`\"']+[\\/])[^\r\n:\"'`]*|"
    r"[^\s\\/:`\"']+)"
)
_GO_SYMBOL = r"[A-Za-z_](?:[\w./()*]|\[[^\r\n\]]*\])*"

_PYTHON_FRAME = re.compile(
    r'^\s*File "(?P<path>[^"\r\n]+)",\s*line (?P<line>\d+)(?:,\s*in (?P<function>[^\r\n,]+?))?\s*$'
)
_AT_LINE = re.compile(r"^\s*at\s+(?P<body>.+?)\s*$")
_LOCATION_SUFFIX = re.compile(
    rf"^(?P<path>{_PATH_PREFIX}\.(?:{_EXT_GROUP})):(?P<line>\d+)(?::\d+)?$"
)
_GO_CALL_LINE = re.compile(
    rf"^(?P<function>{_GO_SYMBOL})\([^()\r\n]*\)\s*$"
)
_GO_CREATED_BY_LINE = re.compile(
    rf"^created by (?P<function>{_GO_SYMBOL})(?:\s+in goroutine \d+)?\s*$"
)
_GO_LOCATION_LINE = re.compile(
    rf"^\s+(?P<path>{_PATH_PREFIX}\.go):(?P<line>\d+)(?:\s+\+0x[0-9a-fA-F]+)?\s*$"
)
_RUBY_FRAME = re.compile(
    rf"^\s*(?:from\s+)?(?P<path>{_PATH_PREFIX}\.rb):(?P<line>\d+):in\s+[`'\x22](?P<function>[^`'\x22\r\n]+)[`'\x22]\s*$"
)
_PHP_FRAME = re.compile(
    rf"^\s*#\d+\s+(?P<path>{_PATH_PREFIX}\.php)\((?P<line>\d+)\):\s*(?P<function>[^\r\n(]+?)(?:\(.*\))?\s*$"
)
_RUST_BACKTRACE_FUNC = re.compile(
    r"^\s*\d+:\s+(?:0x[0-9a-fA-F]+\s+-\s+)?(?P<function>(?:<[A-Za-z_]|[A-Za-z_])[\w:$<>.,\{\}\[\]&* ]*?)\s*$"
)
_RUST_PANIC_FRAME = re.compile(
    rf"^\s*thread\s+'[^']+'\s+panicked\s+at\s+(?:'[^']*',\s*)?(?P<path>{_PATH_PREFIX}\.rs):(?P<line>\d+)(?::\d+)?:?\s*$"
)


@dataclass(frozen=True)
class IncidentFrame:
    path: str
    line: int
    function: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "line": self.line, "function": self.function}


@dataclass(frozen=True)
class Incident:
    incident_id: str
    message: str
    stack_trace: str = ""
    exception_type: str = ""
    runtime: str = ""
    commit_sha: str = ""
    environment: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Incident":
        if not isinstance(payload, dict):
            raise ValueError("incident payload must be a JSON object")
        message = payload.get("message") or payload.get("error") or ""
        if not isinstance(message, str) or not message.strip():
            raise ValueError("incident payload requires a non-empty 'message' or 'error'")
        stack_trace = payload.get("stack_trace") or payload.get("stack") or ""
        if isinstance(stack_trace, list):
            stack_trace = "\n".join(str(line) for line in stack_trace)
        if not isinstance(stack_trace, str):
            raise ValueError("incident 'stack_trace' must be a string or list of strings")
        return cls(
            incident_id=str(payload.get("incident_id") or payload.get("id") or "incident"),
            message=message.strip(),
            stack_trace=stack_trace,
            exception_type=str(payload.get("exception_type") or payload.get("type") or ""),
            runtime=str(payload.get("runtime") or ""),
            commit_sha=str(payload.get("commit_sha") or payload.get("commit") or ""),
            environment=dict(payload.get("environment") or {}),
            metadata=dict(payload.get("metadata") or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "message": self.message,
            "stack_trace": self.stack_trace,
            "exception_type": self.exception_type,
            "runtime": self.runtime,
            "commit_sha": self.commit_sha,
            "environment": self.environment,
            "metadata": self.metadata,
        }


@dataclass
class RepairEvidence:
    path: str
    score: float
    reasons: list[str] = field(default_factory=list)
    frame_lines: list[int] = field(default_factory=list)
    symbols: list[str] = field(default_factory=list)
    excerpt: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "score": round(self.score, 3),
            "reasons": self.reasons,
            "frame_lines": self.frame_lines,
            "symbols": self.symbols,
            "excerpt": self.excerpt,
        }


@dataclass
class RepairContext:
    incident: Incident
    repository_path: str
    evidence: list[RepairEvidence] = field(default_factory=list)
    unmapped_frames: list[IncidentFrame] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident": self.incident.to_dict(),
            "repository_path": self.repository_path,
            "evidence": [item.to_dict() for item in self.evidence],
            "unmapped_frames": [frame.to_dict() for frame in self.unmapped_frames],
        }


def load_incident(path: str) -> Incident:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"failed to load incident JSON: {exc}") from exc
    return Incident.from_dict(payload)


def _clean_frame_path(raw_path: str) -> str:
    path = raw_path.strip()
    if path.startswith("file://"):
        parsed = urlparse(path)
        url_path = unquote(parsed.path or "")
        if re.match(r"^/[A-Za-z]:[\\/]", url_path):
            path = url_path[1:]
        else:
            path = url_path
    return path.strip()


def _build_frame(raw_path: str, raw_line: str, raw_function: str = "") -> IncidentFrame | None:
    path = _clean_frame_path(raw_path)
    line_number = int(raw_line)
    if not path or line_number <= 0:
        return None
    return IncidentFrame(path=path, line=line_number, function=raw_function.strip())


def _parse_at_frame(raw_line: str, rust_default_function: str = "") -> IncidentFrame | None:
    at_match = _AT_LINE.match(raw_line)
    if not at_match:
        return None
    body = at_match.group("body")

    if body.endswith(")"):
        location_text = ""
        function_text = ""
        if " (" in body:
            split_index = body.find(" (")
            function_text = body[:split_index].strip()
            location_text = body[split_index + 2 : -1].strip()
        elif "(" in body:
            split_index = body.find("(")
            candidate_fn = body[:split_index].strip()
            if candidate_fn and not any(ch.isspace() for ch in candidate_fn):
                function_text = candidate_fn
                location_text = body[split_index + 1 : -1].strip()
        if location_text:
            loc_match = _LOCATION_SUFFIX.match(location_text)
            if loc_match:
                cleaned_fn = re.sub(r"^(?:(?:async|new)\s+)+", "", function_text).strip()
                raw_path = loc_match.group("path")
                fallback_fn = rust_default_function if raw_path.lower().endswith(".rs") else ""
                return _build_frame(
                    raw_path,
                    loc_match.group("line"),
                    cleaned_fn or fallback_fn,
                )

    loc_match = _LOCATION_SUFFIX.match(body)
    if loc_match:
        raw_path = loc_match.group("path")
        fallback_fn = rust_default_function if raw_path.lower().endswith(".rs") else ""
        return _build_frame(raw_path, loc_match.group("line"), fallback_fn)
    return None


def extract_stack_frames(stack_trace: str) -> list[IncidentFrame]:
    frames: list[IncidentFrame] = []
    pending_go_function = ""
    pending_rust_function = ""

    for raw_line in stack_trace.splitlines():
        go_func_match = _GO_CALL_LINE.match(raw_line) or _GO_CREATED_BY_LINE.match(raw_line)
        if go_func_match:
            pending_go_function = go_func_match.group("function").strip()
            pending_rust_function = ""
            continue

        rust_func_match = _RUST_BACKTRACE_FUNC.match(raw_line)
        if rust_func_match:
            pending_rust_function = rust_func_match.group("function").strip()
            pending_go_function = ""
            continue

        go_loc_match = _GO_LOCATION_LINE.match(raw_line)
        if go_loc_match:
            frame = _build_frame(go_loc_match.group("path"), go_loc_match.group("line"), pending_go_function)
            pending_go_function = ""
            pending_rust_function = ""
            if frame is not None:
                frames.append(frame)
            continue

        at_frame = _parse_at_frame(raw_line, rust_default_function=pending_rust_function)
        if at_frame is not None:
            pending_go_function = ""
            pending_rust_function = ""
            frames.append(at_frame)
            continue

        pending_go_function = ""
        pending_rust_function = ""
        for pattern in (_PYTHON_FRAME, _RUBY_FRAME, _PHP_FRAME, _RUST_PANIC_FRAME):
            match = pattern.match(raw_line)
            if match:
                frame = _build_frame(
                    match.group("path"),
                    match.group("line"),
                    match.groupdict().get("function") or "",
                )
                if frame is not None:
                    frames.append(frame)
                break

    return frames


def _match_repository_path(frame_path: str, repo_root: str, available_paths: set[str]) -> str | None:
    normalized = os.path.normpath(frame_path)
    if os.path.isabs(normalized):
        try:
            relative = os.path.relpath(normalized, repo_root)
        except ValueError:
            return None
        if relative == os.pardir or relative.startswith(os.pardir + os.sep):
            return None
        normalized = relative
    normalized = normalized.lstrip("./")
    if normalized in available_paths:
        return normalized
    matches = [path for path in available_paths if path.endswith(os.sep + normalized) or normalized.endswith(os.sep + path)]
    return matches[0] if len(matches) == 1 else None


def _graph_distances(graph: DependencyGraph, origins: set[str], maximum_distance: int) -> dict[str, int]:
    distances: dict[str, int] = {path: 0 for path in origins}
    queue = deque(origins)
    while queue:
        path = queue.popleft()
        distance = distances[path]
        if distance >= maximum_distance:
            continue
        neighbors = graph.dependencies(path) + graph.dependents(path)
        for neighbor in neighbors:
            if neighbor not in distances:
                distances[neighbor] = distance + 1
                queue.append(neighbor)
    return distances


def _read_excerpt(repo_root: str, path: str, line: int, radius: int = 2) -> str:
    full_path = Path(repo_root, path).resolve()
    root = Path(repo_root).resolve()
    if root not in full_path.parents and full_path != root:
        return ""
    try:
        lines = full_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    start = max(line - radius, 1)
    end = min(line + radius, len(lines))
    return "\n".join(f"{number}: {lines[number - 1]}" for number in range(start, end + 1))


def build_repair_context(
    incident: Incident,
    graph: DependencyGraph,
    profiles: dict[str, FileProfile],
    repo_root: str,
    *,
    top_n: int = 10,
    maximum_graph_distance: int = 2,
) -> RepairContext:
    available_paths = set(profiles)
    mapped: dict[str, list[int]] = {}
    unmapped: list[IncidentFrame] = []
    for frame in extract_stack_frames(incident.stack_trace):
        path = _match_repository_path(frame.path, repo_root, available_paths)
        if path is None:
            unmapped.append(frame)
        else:
            mapped.setdefault(path, []).append(frame.line)

    scores: dict[str, float] = {}
    reasons: dict[str, list[str]] = {}
    for path, lines in mapped.items():
        scores[path] = 100.0
        reasons[path] = [f"stack frame at line {line}" for line in sorted(set(lines))]

    for path, distance in _graph_distances(graph, set(mapped), maximum_graph_distance).items():
        if distance == 0:
            continue
        scores[path] = scores.get(path, 0.0) + 30.0 / distance
        reasons.setdefault(path, []).append(f"dependency graph distance {distance} from stack frame")

    query = " ".join(part for part in (incident.exception_type, incident.message) if part)
    if query:
        for match in query_codebase(profiles, query, top_n=top_n):
            path = match.profile.file
            scores[path] = scores.get(path, 0.0) + match.final_score / 5.0
            reasons.setdefault(path, []).extend(match.match_reasons)

    ranked = sorted(scores, key=lambda path: (-scores[path], path))[:top_n]
    evidence: list[RepairEvidence] = []
    for path in ranked:
        profile = profiles[path]
        frame_lines = sorted(set(mapped.get(path, [])))
        symbols = profile.functions + profile.classes + profile.interfaces + profile.structs
        evidence.append(
            RepairEvidence(
                path=path,
                score=scores[path],
                reasons=list(dict.fromkeys(reasons.get(path, []))),
                frame_lines=frame_lines,
                symbols=symbols[:25],
                excerpt=_read_excerpt(repo_root, path, frame_lines[0]) if frame_lines else "",
            )
        )
    return RepairContext(incident=incident, repository_path=repo_root, evidence=evidence, unmapped_frames=unmapped)
