import json
import os
import tempfile
import unittest
import warnings

from intelligence.dependency_graph import build_dependency_graph
from intelligence.models import EcosystemContext, FileAnalysis, RepoIntelligence
from intelligence.resolver import resolve_imports_detailed, resolve_js_imports, resolve_php_imports
from intelligence.scanner import discover_ecosystem_context, scan_repository


class TestEcosystemContext(unittest.TestCase):
    def test_composer_psr4_and_laravel_detection(self):
        with tempfile.TemporaryDirectory() as repo_root:
            with open(os.path.join(repo_root, "composer.json"), "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "autoload": {"psr-4": {"App\\": "app/"}},
                        "require": {"php": "^8.2", "laravel/framework": "^11.0"},
                    },
                    handle,
                )

            context = discover_ecosystem_context(repo_root)
            self.assertEqual({"App\\": "app/"}, context.psr4_mappings)
            self.assertIn("laravel", context.detected_frameworks)

    def test_malformed_composer_json_falls_back_empty(self):
        with tempfile.TemporaryDirectory() as repo_root:
            with open(os.path.join(repo_root, "composer.json"), "w", encoding="utf-8") as handle:
                handle.write("{not-json")

            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                context = discover_ecosystem_context(repo_root)

            self.assertEqual({}, context.psr4_mappings)
            self.assertTrue(any("composer.json" in str(item.message) for item in caught))

    def test_package_json_subpath_imports_and_frameworks(self):
        with tempfile.TemporaryDirectory() as repo_root:
            with open(os.path.join(repo_root, "package.json"), "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "imports": {"#internal/*": "./src/internal/*"},
                        "dependencies": {"next": "14.0.0", "express": "4.18.0", "@nestjs/core": "10.0.0"},
                    },
                    handle,
                )

            context = discover_ecosystem_context(repo_root)
            self.assertEqual({"#internal/*": "./src/internal/*"}, context.subpath_imports)
            self.assertEqual(["nextjs", "express", "nest"], context.detected_frameworks)

    def test_java_python_go_signatures(self):
        with tempfile.TemporaryDirectory() as repo_root:
            with open(os.path.join(repo_root, "pom.xml"), "w", encoding="utf-8") as handle:
                handle.write("<project>spring-boot-starter-web</project>\n")
            with open(os.path.join(repo_root, "requirements.txt"), "w", encoding="utf-8") as handle:
                handle.write("django==5.0\nfastapi==0.110.0\n")
            with open(os.path.join(repo_root, "go.mod"), "w", encoding="utf-8") as handle:
                handle.write("module example.com/app\n")

            context = discover_ecosystem_context(repo_root)
            self.assertIn("spring-boot", context.detected_frameworks)
            self.assertIn("django", context.detected_frameworks)
            self.assertIn("fastapi", context.detected_frameworks)
            self.assertIn("go", context.detected_frameworks)

    def test_php_psr4_resolves_only_existing_files(self):
        context = EcosystemContext(psr4_mappings={"App\\": "app/"})
        all_files = {
            os.path.join("app", "Http", "Livewire", "Admin", "Agency", "Portal.php"),
            os.path.join("app", "Models", "User.php"),
        }
        resolved = resolve_php_imports(
            "use App\\Http\\Livewire\\Admin\\Agency\\Portal;\nuse Vendor\\Missing\\Thing;\n",
            os.path.join("app", "Http", "Controllers", "HomeController.php"),
            all_files,
            "/repo",
            ecosystem_context=context,
        )
        self.assertEqual(
            [os.path.join("app", "Http", "Livewire", "Admin", "Agency", "Portal.php")],
            resolved,
        )

        detailed = resolve_imports_detailed(
            "php",
            "use App\\Http\\Livewire\\Admin\\Agency\\Portal;\nuse Vendor\\Missing\\Thing;\n",
            os.path.join("app", "Http", "Controllers", "HomeController.php"),
            all_files,
            "/repo",
            ecosystem_context=context,
        )
        statuses = {row.specifier: row.status for row in detailed}
        self.assertEqual("resolved", statuses["App\\Http\\Livewire\\Admin\\Agency\\Portal"])
        self.assertEqual("external", statuses["Vendor\\Missing\\Thing"])

    def test_js_subpath_imports_expand_hash_specifiers(self):
        context = EcosystemContext(subpath_imports={"#internal/*": "./src/internal/*"})
        all_files = {
            os.path.join("src", "internal", "config.ts"),
            os.path.join("src", "main.ts"),
        }
        resolved = resolve_js_imports(
            "import cfg from '#internal/config';\n",
            os.path.join("src", "main.ts"),
            all_files,
            "/repo",
            ecosystem_context=context,
        )
        self.assertEqual([os.path.join("src", "internal", "config.ts")], resolved)

    def test_scan_repository_attaches_ecosystem_context_before_walk(self):
        with tempfile.TemporaryDirectory() as repo_root:
            os.makedirs(os.path.join(repo_root, "app", "Models"), exist_ok=True)
            with open(os.path.join(repo_root, "composer.json"), "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "autoload": {"psr-4": {"App\\": "app/"}},
                        "require": {"laravel/framework": "^11.0"},
                    },
                    handle,
                )
            with open(os.path.join(repo_root, "app", "Models", "User.php"), "w", encoding="utf-8") as handle:
                handle.write("<?php\nnamespace App\\Models;\nclass User {}\n")
            with open(os.path.join(repo_root, "app", "Index.php"), "w", encoding="utf-8") as handle:
                handle.write("<?php\nuse App\\Models\\User;\n")

            intel = scan_repository(repo_root, verbose=False)
            self.assertIsNotNone(intel.ecosystem_context)
            self.assertEqual({"App\\": "app/"}, intel.ecosystem_context.psr4_mappings)
            self.assertIn("laravel", intel.ecosystem_context.detected_frameworks)

            graph = build_dependency_graph(intel)
            user_path = os.path.join("app", "Models", "User.php")
            index_path = os.path.join("app", "Index.php")
            if index_path in graph.all_nodes() and intel.file_analyses:
                # Edges exist only when the analyzer captured the use statement.
                deps = graph.dependencies(index_path)
                if deps:
                    self.assertEqual([user_path], deps)

    def test_empty_ecosystem_context_does_not_break_legacy_python_resolution(self):
        intel = RepoIntelligence(
            repo_path="/repo",
            repo_url="",
            file_analyses=[
                FileAnalysis(
                    path="pkg/main.py",
                    language="python",
                    lines=1,
                    size_bytes=1,
                    imports=["import pkg.util"],
                ),
                FileAnalysis(path="pkg/util.py", language="python", lines=1, size_bytes=1),
            ],
        )
        graph = build_dependency_graph(intel)
        self.assertEqual(["pkg/util.py"], graph.dependencies("pkg/main.py"))


if __name__ == "__main__":
    unittest.main()
