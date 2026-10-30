import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from intelligence.dependency_graph import build_dependency_graph
from intelligence.file_profile import build_file_profiles
from intelligence.query_engine import query_codebase
from intelligence.risk_scorer import compute_score_breakdown
from intelligence.scanner import scan_repository

ROOT = Path(__file__).resolve().parents[1]
CLICK_FIXTURE = ROOT / ".repo_cache" / "click"


class TestCLIIntegration(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, "main.py", *args],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONPATH": str(ROOT)},
        )

    @unittest.skipUnless(CLICK_FIXTURE.is_dir(), "Click fixture not present")
    def test_click_fixture_end_to_end_cli_workflow(self):
        result = self.run_cli(
            "--local",
            str(CLICK_FIXTURE),
            "--graph",
            "--list-critical",
            "--query",
            "error",
        )

        self.assertEqual(0, result.returncode, msg=result.stderr or result.stdout)
        output = result.stdout + result.stderr

        self.assertIn("Scanning local repository", output)
        self.assertIn("Running intelligence scan", output)
        self.assertIn("Files:", output)
        self.assertIn("Nodes (files):", output)
        self.assertIn("Edges (import links):", output)
        self.assertIn("Isolated files:", output)
        self.assertIn("MOST CRITICAL FILES", output)
        self.assertIn("CODEBASE QUERY RESULTS", output)
        self.assertIn("Query:", output)
        self.assertIn("error", output.lower())

    def test_cli_handles_missing_local_directory(self):
        missing = ROOT / "does_not_exist_for_cli_test"
        result = self.run_cli("--local", str(missing))

        self.assertNotEqual(0, result.returncode)
        self.assertIn("is not a valid directory", result.stderr)

    def test_cli_supports_minimal_local_repository(self):
        with tempfile.TemporaryDirectory() as repo_root:
            repo = Path(repo_root)
            (repo / "main.py").write_text("def main():\n    return 42\n", encoding="utf-8")

            result = self.run_cli("--local", str(repo), "--graph", "--list-critical", "--query", "error")

            self.assertEqual(0, result.returncode, msg=result.stderr or result.stdout)
            output = result.stdout + result.stderr
            self.assertIn("Files:", output)
            self.assertIn("Nodes (files):", output)
            self.assertIn("CODEBASE QUERY RESULTS", output)
            self.assertIn("relevant files", output)
            self.assertIn("No files matched the query", output)

    def test_cli_explains_deterministic_incident_context(self):
        with tempfile.TemporaryDirectory() as repo_root:
            repo = Path(repo_root)
            (repo / "app").mkdir()
            (repo / "app" / "main.py").write_text(
                "from app.service import execute\n\ndef run():\n    return execute()\n",
                encoding="utf-8",
            )
            (repo / "app" / "service.py").write_text(
                "def execute():\n    raise RuntimeError('broken')\n",
                encoding="utf-8",
            )
            incident_path = repo / "incident.json"
            incident_path.write_text(
                json.dumps({
                    "id": "incident-1",
                    "error": "execute failed",
                    "stack": 'File "app/main.py", line 4, in run',
                }),
                encoding="utf-8",
            )

            result = self.run_cli(
                "--local", str(repo), "--incident", str(incident_path), "--explain-context",
            )

            self.assertEqual(0, result.returncode, msg=result.stderr or result.stdout)
            output = result.stdout + result.stderr
            self.assertIn('"incident_id": "incident-1"', output)
            self.assertIn('"path": "app/main.py"', output)

            patch_plan_path = repo / "patch-plan.json"
            patch_plan_path.write_text(
                json.dumps({
                    "diagnosis": "Return a handled failure.",
                    "files_to_modify": ["app/main.py"],
                    "unified_diff": "--- a/app/main.py\n+++ b/app/main.py\n@@ -1 +1 @@\n-old\n+new\n",
                    "tests_to_run": ["python -m unittest tests.test_cli_integration"],
                    "confidence": 0.8,
                }),
                encoding="utf-8",
            )
            run_root = repo / ".asre" / "runs"
            plan_result = self.run_cli(
                "--local", str(repo), "--incident", str(incident_path), "--patch-plan", str(patch_plan_path),
                "--repair-run-dir", str(run_root),
            )
            self.assertEqual(0, plan_result.returncode, msg=plan_result.stderr or plan_result.stdout)
            self.assertIn('"valid": true', plan_result.stdout + plan_result.stderr)
            self.assertTrue((run_root / "incident-1" / "repair-context.json").is_file())

    def test_graph_and_profiles_are_self_consistent_for_temp_repo(self):
        with tempfile.TemporaryDirectory() as repo_root:
            repo = Path(repo_root)
            pkg = repo / "pkg"
            pkg.mkdir()
            (pkg / "__init__.py").write_text("", encoding="utf-8")
            (pkg / "errors.py").write_text(
                "def handle_error():\n    return 'boom'\n",
                encoding="utf-8",
            )
            (pkg / "runner.py").write_text(
                "from pkg.errors import handle_error\n\ndef run():\n    return handle_error()\n",
                encoding="utf-8",
            )
            (pkg / "helper.py").write_text("VALUE = 1\n", encoding="utf-8")

            intel = scan_repository(str(repo), repo_url="https://example.invalid")
            graph = build_dependency_graph(intel)
            profiles = build_file_profiles(graph, intel, {}, {})

            self.assertEqual(len(graph.all_nodes()), graph.stats()["total_nodes"])
            self.assertEqual(
                graph.stats()["total_edges"],
                sum(len(v) for v in graph._deps.values()),
            )

            for path in graph.all_nodes():
                self.assertIn(path, profiles)
                profile = profiles[path]
                self.assertEqual(len(graph.dependencies(path)), len(profile.imports))
                self.assertEqual(len(graph.dependents(path)), len(profile.imported_by))
                self.assertEqual(len(graph.transitive_dependents(path)), len(profile.transitive_consumers))

                for target in graph.dependencies(path):
                    self.assertIn(target, graph.all_nodes())

                for source in graph.dependents(path):
                    self.assertIn(source, graph.all_nodes())

    @unittest.skipUnless(CLICK_FIXTURE.is_dir(), "Click fixture not present")
    def test_click_scan_accounting_matches_analyzed_file_contract(self):
        intel = scan_repository(str(CLICK_FIXTURE), repo_url="https://example.invalid")
        self.assertEqual(len(intel.file_analyses), intel.total_files)
        analyzed = [fa for fa in intel.file_analyses if fa.language != "unknown"]
        self.assertGreater(len(analyzed), 0)
        self.assertEqual(len(analyzed), sum(1 for fa in intel.file_analyses if fa.language != "unknown"))
        self.assertGreaterEqual(intel.total_files, len(analyzed))

    def test_risk_scoring_is_deterministic_with_known_relative_order(self):
        low = compute_score_breakdown(
            path="pkg/low.py",
            direct_dep_count=1,
            transitive_dep_count=0,
            recent_change_count=0,
            public_symbol_count=1,
        )
        high = compute_score_breakdown(
            path="pkg/high.py",
            direct_dep_count=5,
            transitive_dep_count=10,
            recent_change_count=3,
            public_symbol_count=5,
        )

        self.assertLess(low.total, high.total)
        self.assertEqual(6, low.total)
        self.assertEqual(59, high.total)

    def test_query_engine_documents_blank_and_non_matching_query_behavior(self):
        profiles = {
            "pkg/errors.py": type("P", (), {"basename": "errors.py", "functions": ["handle_error"], "classes": [], "interfaces": [], "structs": [], "imports": [], "imported_by": [], "todos": [], "risk_score": 10})(),
            "pkg/other.py": type("P", (), {"basename": "other.py", "functions": ["do_work"], "classes": [], "interfaces": [], "structs": [], "imports": [], "imported_by": [], "todos": [], "risk_score": 0})(),
        }

        blank_matches = query_codebase(profiles, "   ")
        empty_matches = query_codebase(profiles, "")
        non_matching = query_codebase(profiles, "not-present-in-any-file")

        self.assertGreater(len(blank_matches), 0)
        self.assertGreater(len(empty_matches), 0)
        self.assertEqual([], non_matching)

        ranked = query_codebase(profiles, "error")
        self.assertGreater(len(ranked), 0)
        self.assertEqual("errors.py", ranked[0].profile.basename)

    def test_cli_empty_query_is_ignored_but_whitespace_query_is_broad_match(self):
        with tempfile.TemporaryDirectory() as repo_root:
            repo = Path(repo_root)
            (repo / "main.py").write_text("def main():\n    return 42\n", encoding="utf-8")

            empty_result = self.run_cli("--local", str(repo), "--query", "")
            self.assertEqual(0, empty_result.returncode)
            self.assertNotIn("CODEBASE QUERY RESULTS", empty_result.stdout + empty_result.stderr)

            whitespace_result = self.run_cli("--local", str(repo), "--query", "   ")
            self.assertEqual(0, whitespace_result.returncode)
            output = whitespace_result.stdout + whitespace_result.stderr
            self.assertIn("CODEBASE QUERY RESULTS", output)
            self.assertIn("main.py", output)


if __name__ == "__main__":
    unittest.main()
