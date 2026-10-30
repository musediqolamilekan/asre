import unittest

from repair.incident_mapper import Incident, RepairContext, RepairEvidence
from repair.patch_planner import PatchPlan, validate_patch_plan


class TestPatchPlanner(unittest.TestCase):
    def setUp(self):
        self.context = RepairContext(
            incident=Incident("inc-1", "broken"),
            repository_path="/repo",
            evidence=[RepairEvidence(path="app/service.py", score=100)],
        )
        self.diff = "--- a/app/service.py\n+++ b/app/service.py\n@@ -1 +1 @@\n-old\n+new\n"

    def test_valid_plan_is_accepted(self):
        plan = PatchPlan("Fix service failure", ("app/service.py",), self.diff, ("python -m unittest tests.test_service",), 0.9)
        validation = validate_patch_plan(plan, self.context)
        self.assertTrue(validation.valid, validation.errors)

    def test_plan_rejects_files_outside_context_and_unsafe_commands(self):
        plan = PatchPlan(
            "Change unrelated file",
            ("app/other.py",),
            "--- a/app/other.py\n+++ b/app/other.py\n@@ -1 +1 @@\n-old\n+new\n",
            ("python -m unittest; rm -rf /",),
            0.8,
        )
        validation = validate_patch_plan(plan, self.context)
        self.assertFalse(validation.valid)
        self.assertTrue(any("outside repair context" in error for error in validation.errors))
        self.assertTrue(any("not allowlisted" in error for error in validation.errors))

    def test_plan_rejects_path_traversal_and_diff_mismatch(self):
        plan = PatchPlan("Escape", ("../outside.py",), self.diff, ("pytest tests",), 1.2)
        validation = validate_patch_plan(plan, self.context)
        self.assertFalse(validation.valid)
        self.assertTrue(any("unsafe planned file path" in error for error in validation.errors))
        self.assertTrue(any("exactly match" in error for error in validation.errors))
        self.assertTrue(any("confidence" in error for error in validation.errors))


if __name__ == "__main__":
    unittest.main()
