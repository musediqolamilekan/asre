"""Isolated application and verification of validated patch plans."""

from __future__ import annotations

import shutil
import shlex
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .incident_mapper import RepairContext
from .patch_planner import PatchPlan, PatchPlanValidation, validate_patch_plan


@dataclass(frozen=True)
class CommandResult:
    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    def to_dict(self) -> dict:
        return {
            "command": list(self.command),
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timed_out": self.timed_out,
        }


@dataclass(frozen=True)
class PatchExecutionResult:
    status: str
    validation: PatchPlanValidation
    revision: str = ""
    commands: tuple[CommandResult, ...] = ()
    worktree_removed: bool = False
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "validation": self.validation.to_dict(),
            "revision": self.revision,
            "commands": [result.to_dict() for result in self.commands],
            "worktree_removed": self.worktree_removed,
            "error": self.error,
        }


def _truncate(output: str, limit: int = 20000) -> str:
    if len(output) <= limit:
        return output
    return output[:limit] + "\n[output truncated]"


def _run(command: list[str], *, cwd: Optional[str] = None, input_text: Optional[str] = None, timeout: int = 120) -> CommandResult:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return CommandResult(
            tuple(command),
            completed.returncode,
            _truncate(completed.stdout),
            _truncate(completed.stderr),
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            tuple(command),
            124,
            _truncate(exc.stdout or ""),
            _truncate(exc.stderr or ""),
            True,
        )
    except OSError as exc:
        return CommandResult(tuple(command), 127, "", str(exc))


def execute_patch_plan(
    plan: PatchPlan,
    context: RepairContext,
    *,
    command_timeout: int = 120,
) -> PatchExecutionResult:
    validation = validate_patch_plan(plan, context)
    if not validation.valid:
        return PatchExecutionResult("rejected", validation, error="patch plan validation failed")

    repository = Path(context.repository_path).resolve()
    root_result = _run(["git", "-C", str(repository), "rev-parse", "--show-toplevel"])
    if root_result.returncode != 0:
        return PatchExecutionResult("error", validation, commands=(root_result,), error="repository is not a Git worktree")
    repository = Path(root_result.stdout.strip())
    requested_revision = context.incident.commit_sha or "HEAD"
    revision_result = _run(["git", "-C", str(repository), "rev-parse", "--verify", f"{requested_revision}^{{commit}}"])
    if revision_result.returncode != 0:
        return PatchExecutionResult("error", validation, commands=(root_result, revision_result), error="incident revision is unavailable")
    revision = revision_result.stdout.strip()

    commands: list[CommandResult] = [root_result, revision_result]
    temporary_root = Path(tempfile.mkdtemp(prefix="asre-patch-"))
    worktree = temporary_root / "worktree"
    worktree_added = False
    worktree_removed = False
    status = "error"
    error = ""
    try:
        add_result = _run(["git", "-C", str(repository), "worktree", "add", "--detach", str(worktree), revision])
        commands.append(add_result)
        if add_result.returncode != 0:
            error = "failed to create isolated worktree"
        else:
            worktree_added = True
            check_result = _run(
                ["git", "apply", "--check", "--whitespace=error", "-"],
                cwd=str(worktree),
                input_text=plan.unified_diff,
            )
            commands.append(check_result)
            if check_result.returncode != 0:
                status = "failed"
                error = "patch does not apply cleanly"
            else:
                apply_result = _run(
                    ["git", "apply", "--whitespace=error", "-"],
                    cwd=str(worktree),
                    input_text=plan.unified_diff,
                )
                commands.append(apply_result)
                if apply_result.returncode != 0:
                    status = "failed"
                    error = "patch application failed"
                else:
                    for test_command in plan.tests_to_run:
                        test_result = _run(shlex.split(test_command), cwd=str(worktree), timeout=command_timeout)
                        commands.append(test_result)
                    test_results = commands[4:]
                    status = "verified" if all(result.returncode == 0 for result in test_results) else "failed"
                    error = "" if status == "verified" else "one or more verification commands failed"
    finally:
        if worktree_added:
            remove_result = _run(["git", "-C", str(repository), "worktree", "remove", "--force", str(worktree)])
            commands.append(remove_result)
            worktree_removed = remove_result.returncode == 0
        shutil.rmtree(temporary_root, ignore_errors=True)
    return PatchExecutionResult(status, validation, revision, tuple(commands), worktree_removed, error)
