"""Persistent, auditable artifacts for incident repair attempts."""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .incident_mapper import RepairContext
from .patch_executor import PatchExecutionResult
from .patch_planner import PatchPlan, PatchPlanValidation


_RUN_NAME = re.compile(r"[^A-Za-z0-9._-]+")


@dataclass(frozen=True)
class RepairRun:
    path: str
    status: str
    incident_id: str

    def to_dict(self) -> dict:
        return {"path": self.path, "status": self.status, "incident_id": self.incident_id}


def _run_name(incident_id: str) -> str:
    normalized = _RUN_NAME.sub("-", incident_id).strip(".-")
    return normalized[:100] or "incident"


def _next_run_path(root: Path, incident_id: str) -> Path:
    base = _run_name(incident_id)
    candidate = root / base
    sequence = 1
    while candidate.exists():
        candidate = root / f"{base}-{sequence}"
        sequence += 1
    return candidate


def _status(validation: Optional[PatchPlanValidation], execution: Optional[PatchExecutionResult]) -> str:
    if execution is not None:
        return execution.status
    if validation is not None and not validation.valid:
        return "rejected"
    return "needs-review"


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def save_repair_run(
    root_directory: str,
    context: RepairContext,
    *,
    plan: Optional[PatchPlan] = None,
    validation: Optional[PatchPlanValidation] = None,
    execution: Optional[PatchExecutionResult] = None,
) -> RepairRun:
    root = Path(root_directory).resolve()
    root.mkdir(parents=True, exist_ok=True)
    destination = _next_run_path(root, context.incident.incident_id)
    temporary_directory = Path(tempfile.mkdtemp(prefix=".asre-run-", dir=root))
    status = _status(validation, execution)
    try:
        _write_json(temporary_directory / "incident.json", context.incident.to_dict())
        _write_json(temporary_directory / "repair-context.json", context.to_dict())
        verification = execution.to_dict() if execution is not None else {
            "status": status,
            "validation": validation.to_dict() if validation is not None else None,
        }
        _write_json(temporary_directory / "verification.json", verification)
        if plan is not None:
            _write_json(temporary_directory / "patch-plan.json", plan.to_dict())
            (temporary_directory / "patch.diff").write_text(plan.unified_diff, encoding="utf-8")
        _write_json(temporary_directory / "run.json", {
            "incident_id": context.incident.incident_id,
            "status": status,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
        os.replace(temporary_directory, destination)
    except Exception:
        shutil.rmtree(temporary_directory, ignore_errors=True)
        raise
    return RepairRun(str(destination), status, context.incident.incident_id)
