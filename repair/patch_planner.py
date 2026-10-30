"""Provider-neutral patch-plan contracts and deterministic safety validation."""

from __future__ import annotations

import json
import posixpath
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from .incident_mapper import RepairContext


_DIFF_HEADER = re.compile(r"^(---|\+\+\+) (?:a/|b/)?(?P<path>[^\t\n]+)(?:\t.*)?$", re.MULTILINE)
_HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@", re.MULTILINE)
_COMMAND_FORBIDDEN = re.compile(r"[;&|<>`$\r\n]")
_DEFAULT_TEST_PREFIXES = (
    ("python", "-m", "unittest"),
    ("venv/bin/python", "-m", "unittest"),
    ("pytest",),
    ("venv/bin/pytest",),
)


class PatchPlanner(Protocol):
    """An LLM or human adapter that produces a structured patch plan."""

    def plan(self, context: RepairContext) -> "PatchPlan":
        """Return a patch plan constrained to the supplied repair context."""


@dataclass(frozen=True)
class PatchPlan:
    diagnosis: str
    files_to_modify: tuple[str, ...]
    unified_diff: str
    tests_to_run: tuple[str, ...]
    confidence: float

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "PatchPlan":
        if not isinstance(payload, dict):
            raise ValueError("patch plan must be a JSON object")
        diagnosis = payload.get("diagnosis")
        files = payload.get("files_to_modify")
        diff = payload.get("unified_diff")
        tests = payload.get("tests_to_run")
        confidence = payload.get("confidence")
        if not isinstance(diagnosis, str) or not diagnosis.strip():
            raise ValueError("patch plan requires a non-empty 'diagnosis'")
        if not isinstance(files, list) or not all(isinstance(path, str) for path in files):
            raise ValueError("patch plan 'files_to_modify' must be a list of strings")
        if not isinstance(diff, str) or not diff.strip():
            raise ValueError("patch plan requires a non-empty 'unified_diff'")
        if not isinstance(tests, list) or not all(isinstance(command, str) for command in tests):
            raise ValueError("patch plan 'tests_to_run' must be a list of strings")
        if not isinstance(confidence, (int, float)) or isinstance(confidence, bool):
            raise ValueError("patch plan 'confidence' must be a number")
        return cls(diagnosis.strip(), tuple(files), diff, tuple(tests), float(confidence))

    def to_dict(self) -> dict[str, Any]:
        return {
            "diagnosis": self.diagnosis,
            "files_to_modify": list(self.files_to_modify),
            "unified_diff": self.unified_diff,
            "tests_to_run": list(self.tests_to_run),
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class PatchPlanValidation:
    valid: bool
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"valid": self.valid, "errors": list(self.errors)}


def load_patch_plan(path: str) -> PatchPlan:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"failed to load patch plan JSON: {exc}") from exc
    return PatchPlan.from_dict(payload)


def _normalise_repo_path(path: str) -> str | None:
    if not path or "\\" in path:
        return None
    normalized = posixpath.normpath(path)
    if normalized in {".", ".."} or normalized.startswith("../") or normalized.startswith("/"):
        return None
    return normalized


def _diff_paths(unified_diff: str) -> tuple[set[str], list[str]]:
    errors: list[str] = []
    if "GIT binary patch" in unified_diff or "Binary files " in unified_diff:
        errors.append("binary patches are not supported")
    headers = list(_DIFF_HEADER.finditer(unified_diff))
    if len(headers) < 2 or len(headers) % 2:
        errors.append("unified diff must contain paired --- and +++ file headers")
        return set(), errors
    if not _HUNK_HEADER.search(unified_diff):
        errors.append("unified diff must contain at least one @@ hunk header")
    paths: set[str] = set()
    for before, after in zip(headers[::2], headers[1::2]):
        if before.group(1) != "---" or after.group(1) != "+++":
            errors.append("unified diff file headers must be ordered as --- then +++")
            continue
        before_path = _normalise_repo_path(before.group("path"))
        after_path = _normalise_repo_path(after.group("path"))
        if before_path is None or after_path is None:
            errors.append("unified diff contains an unsafe file path")
            continue
        if before_path != after_path:
            errors.append("renames, additions, and deletions are not supported in patch plans")
            continue
        paths.add(before_path)
    return paths, errors


def _is_allowed_test_command(command: str, prefixes: tuple[tuple[str, ...], ...]) -> bool:
    if not command.strip() or _COMMAND_FORBIDDEN.search(command):
        return False
    try:
        tokens = tuple(shlex.split(command))
    except ValueError:
        return False
    return any(tokens[:len(prefix)] == prefix for prefix in prefixes)


def validate_patch_plan(
    plan: PatchPlan,
    context: RepairContext,
    *,
    allowed_test_prefixes: tuple[tuple[str, ...], ...] = _DEFAULT_TEST_PREFIXES,
) -> PatchPlanValidation:
    errors: list[str] = []
    allowed_paths = {item.path for item in context.evidence}
    planned_paths: set[str] = set()
    for path in plan.files_to_modify:
        normalized = _normalise_repo_path(path)
        if normalized is None:
            errors.append(f"unsafe planned file path: {path!r}")
        else:
            planned_paths.add(normalized)
    if not planned_paths:
        errors.append("patch plan must modify at least one file")
    if len(planned_paths) != len(plan.files_to_modify):
        errors.append("patch plan file paths must be unique")
    for path in sorted(planned_paths - allowed_paths):
        errors.append(f"planned file is outside repair context: {path}")

    diff_paths, diff_errors = _diff_paths(plan.unified_diff)
    errors.extend(diff_errors)
    if diff_paths != planned_paths:
        errors.append("files_to_modify must exactly match unified diff file paths")

    if not 0.0 <= plan.confidence <= 1.0:
        errors.append("confidence must be between 0 and 1")
    if not plan.tests_to_run:
        errors.append("patch plan must include at least one verification command")
    for command in plan.tests_to_run:
        if not _is_allowed_test_command(command, allowed_test_prefixes):
            errors.append(f"verification command is not allowlisted: {command!r}")
    return PatchPlanValidation(not errors, tuple(errors))
