import os
import subprocess
import tempfile
import unittest

from repair.incident_mapper import Incident, RepairContext, RepairEvidence
from repair.patch_executor import execute_patch_plan
from repair.patch_planner import PatchPlan


class TestPatchExecutor(unittest.TestCase):
    def _create_repository(self):
        directory = tempfile.TemporaryDirectory()
        repo = directory.name
        os.makedirs(os.path.join(repo, "app"))
        os.makedirs(os.path.join(repo, "tests"))
        with open(os.path.join(repo, "app", "service.py"), "w", encoding="utf-8") as handle:
            handle.write("VALUE = 1\n")
        with open(os.path.join(repo, "tests", "test_service.py"), "w", encoding="utf-8") as handle:
            handle.write(
                "import unittest\nfrom pathlib import Path\n\n"
                "class ServiceTest(unittest.TestCase):\n"
                "    def test_value(self):\n"
                "        self.assertIn('VALUE = 2', Path('app/service.py').read_text())\n"
            )
        for command in (
            ["git", "init"],
            ["git", "config", "user.email", "asre@example.invalid"],
            ["git", "config", "user.name", "ASRE Test"],
            ["git", "add", "."],
            ["git", "commit", "-m", "initial"],
        ):
            subprocess.run(command, cwd=repo, check=True, capture_output=True, text=True)
        return directory

    def _context(self, repository):
        return RepairContext(
            incident=Incident("inc-1", "service failure"),
            repository_path=repository,
            evidence=[RepairEvidence(path="app/service.py", score=100)],
        )

    def test_verified_patch_runs_in_removed_worktree_without_mutating_source(self):
        directory = self._create_repository()
        self.addCleanup(directory.cleanup)
        plan = PatchPlan(
            "Update service value",
            ("app/service.py",),
            "--- a/app/service.py\n+++ b/app/service.py\n@@ -1 +1 @@\n-VALUE = 1\n+VALUE = 2\n",
            ("python -m unittest discover -s tests",),
            0.9,
        )

        result = execute_patch_plan(plan, self._context(directory.name))

        self.assertEqual("verified", result.status, result.to_dict())
        self.assertTrue(result.worktree_removed)
        with open(os.path.join(directory.name, "app", "service.py"), encoding="utf-8") as handle:
            self.assertEqual("VALUE = 1\n", handle.read())

    def test_invalid_plan_is_rejected_before_git_commands(self):
        directory = self._create_repository()
        self.addCleanup(directory.cleanup)
        plan = PatchPlan(
            "Unsafe target",
            ("outside.py",),
            "--- a/outside.py\n+++ b/outside.py\n@@ -1 +1 @@\n-old\n+new\n",
            ("python -m unittest",),
            0.5,
        )

        result = execute_patch_plan(plan, self._context(directory.name))

        self.assertEqual("rejected", result.status)
        self.assertEqual((), result.commands)


if __name__ == "__main__":
    unittest.main()
