import json
import os
import tempfile
import unittest

from repair.incident_mapper import Incident, RepairContext, RepairEvidence
from repair.patch_planner import PatchPlan, validate_patch_plan
from repair.repair_runs import save_repair_run


class TestRepairRuns(unittest.TestCase):
    def test_save_repair_run_writes_complete_review_artifact(self):
        context = RepairContext(
            incident=Incident("incident/one", "broken"),
            repository_path="/repo",
            evidence=[RepairEvidence(path="app/service.py", score=100)],
        )
        plan = PatchPlan(
            "Fix service",
            ("app/service.py",),
            "--- a/app/service.py\n+++ b/app/service.py\n@@ -1 +1 @@\n-old\n+new\n",
            ("python -m unittest tests.test_service",),
            0.8,
        )
        validation = validate_patch_plan(plan, context)

        with tempfile.TemporaryDirectory() as directory:
            run = save_repair_run(directory, context, plan=plan, validation=validation)

            self.assertEqual("needs-review", run.status)
            self.assertTrue(run.path.endswith("incident-one"))
            self.assertEqual(
                {"incident.json", "repair-context.json", "patch-plan.json", "patch.diff", "verification.json", "run.json"},
                set(os.listdir(run.path)),
            )
            with open(os.path.join(run.path, "verification.json"), encoding="utf-8") as handle:
                self.assertEqual("needs-review", json.load(handle)["status"])

    def test_repeated_incidents_create_distinct_run_directories(self):
        context = RepairContext(Incident("incident", "broken"), "/repo")
        with tempfile.TemporaryDirectory() as directory:
            first = save_repair_run(directory, context)
            second = save_repair_run(directory, context)
            self.assertNotEqual(first.path, second.path)
            self.assertTrue(second.path.endswith("incident-1"))


if __name__ == "__main__":
    unittest.main()
