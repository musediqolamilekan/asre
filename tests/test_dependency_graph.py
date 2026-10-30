import os
import tempfile
import unittest
from unittest import mock

from intelligence import resolver as resolver_module
from intelligence.dependency_graph import build_dependency_graph
from intelligence.models import FileAnalysis, RepoIntelligence


class TestDependencyGraphSemantics(unittest.TestCase):
    def test_requests_is_unresolved_under_current_contract(self):
        with tempfile.TemporaryDirectory() as repo_root:
            main_path = os.path.join(repo_root, "main.py")
            target_path = os.path.join(repo_root, "pkg", "util.py")
            os.makedirs(os.path.dirname(target_path), exist_ok=True)

            with open(main_path, "w", encoding="utf-8") as handle:
                handle.write("import requests\n")
            with open(target_path, "w", encoding="utf-8") as handle:
                handle.write("VALUE = 1\n")

            all_files = {"main.py", os.path.join("pkg", "util.py")}
            results = resolver_module.resolve_imports_detailed(
                "python",
                "import requests\n",
                main_path,
                all_files,
                repo_root,
            )

            self.assertEqual(1, len(results))
            self.assertEqual("requests", results[0].specifier)
            self.assertEqual("unresolved", results[0].status)
            self.assertEqual("no repository target found", results[0].reason)

    def test_dependency_graph_tracks_unresolved_imports_as_incomplete(self):
        with tempfile.TemporaryDirectory() as repo_root:
            main_path = "main.py"
            util_path = os.path.join("pkg", "util.py")
            pkg_dir = os.path.join(repo_root, "pkg")
            os.makedirs(pkg_dir, exist_ok=True)

            with open(os.path.join(repo_root, main_path), "w", encoding="utf-8") as handle:
                handle.write("import pkg.util\nimport requests\n")

            util_file = os.path.join(repo_root, util_path)
            with open(util_file, "w", encoding="utf-8") as handle:
                handle.write("VALUE = 1\n")

            intel = RepoIntelligence(
                repo_path=repo_root,
                repo_url="https://example.invalid",
                file_analyses=[
                    FileAnalysis(path=main_path, language="python", lines=2, size_bytes=1, imports=["import pkg.util", "import requests"]),
                    FileAnalysis(path=util_path, language="python", lines=1, size_bytes=1, imports=[]),
                ],
            )

            graph = build_dependency_graph(intel)
            self.assertEqual([util_path], graph.dependencies(main_path))
            statuses = [row["status"] for row in graph.import_resolutions(main_path)]
            self.assertIn("resolved", statuses)
            self.assertIn("unresolved", statuses)
            self.assertFalse(graph.dependency_data_complete())
            self.assertFalse(graph.dependency_data_complete(main_path))

    def test_dependency_graph_keeps_error_status_distinct_from_unresolved(self):
        with tempfile.TemporaryDirectory() as repo_root:
            main_path = "main.py"
            util_path = os.path.join("pkg", "util.py")
            pkg_dir = os.path.join(repo_root, "pkg")
            os.makedirs(pkg_dir, exist_ok=True)
            with open(os.path.join(repo_root, main_path), "w", encoding="utf-8") as handle:
                handle.write("import pkg.util\nimport badmodule\n")
            with open(os.path.join(repo_root, util_path), "w", encoding="utf-8") as handle:
                handle.write("VALUE = 1\n")

            intel = RepoIntelligence(
                repo_path=repo_root,
                repo_url="https://example.invalid",
                file_analyses=[
                    FileAnalysis(path=main_path, language="python", lines=2, size_bytes=1, imports=["import pkg.util", "import badmodule"]),
                    FileAnalysis(path=util_path, language="python", lines=1, size_bytes=1, imports=[]),
                ],
            )

            with mock.patch(
                "intelligence.dependency_graph.resolve_imports_detailed",
                return_value=[
                    resolver_module.ImportResolution("pkg.util", "resolved", (util_path,), ""),
                    resolver_module.ImportResolution("badmodule", "error", (), "resolver error: boom"),
                ],
            ):
                graph = build_dependency_graph(intel)

            self.assertEqual([util_path], graph.dependencies(main_path))
            statuses = {row["status"] for row in graph.import_resolutions(main_path)}
            self.assertIn("resolved", statuses)
            self.assertIn("error", statuses)
            self.assertNotIn("unresolved", statuses)
            self.assertTrue(graph.dependency_data_complete())
            self.assertTrue(graph.dependency_data_complete(main_path))

    def test_dependency_graph_status_contract_covers_all_resolution_outcomes(self):
        rows = [
            resolver_module.ImportResolution("resolved_mod", "resolved", ("pkg/resolved.py",), ""),
            resolver_module.ImportResolution("external_mod", "external", (), "classified as external dependency"),
            resolver_module.ImportResolution("missing_mod", "unresolved", (), "no repository target found"),
            resolver_module.ImportResolution("ambiguous_mod", "ambiguous", ("pkg/x.py", "pkg/y.py"), "multiple repository targets matched"),
            resolver_module.ImportResolution("broken_mod", "error", (), "resolver error: boom"),
        ]

        statuses = {row.status for row in rows}
        self.assertEqual(
            {"resolved", "external", "unresolved", "ambiguous", "error"},
            statuses,
        )

        complete = not any(row.status in {"unresolved", "ambiguous"} for row in rows)
        self.assertFalse(complete)
        self.assertTrue(any(row.status == "error" for row in rows))
        self.assertTrue(any(row.status == "external" for row in rows))


if __name__ == "__main__":
    unittest.main()
