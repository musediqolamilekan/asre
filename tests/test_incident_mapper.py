import json
import os
import tempfile
import unittest

from intelligence.dependency_graph import build_dependency_graph
from intelligence.file_profile import build_file_profiles
from intelligence.models import FileAnalysis, RepoIntelligence
from repair.incident_mapper import (
    Incident,
    IncidentFrame,
    _match_repository_path,
    build_repair_context,
    extract_stack_frames,
    load_incident,
)


class TestIncidentMapper(unittest.TestCase):
    def _graph_and_profiles(self, repo_root):
        intel = RepoIntelligence(
            repo_path=repo_root,
            repo_url="",
            file_analyses=[
                FileAnalysis("app/main.py", "python", 12, 1, functions=["run"], imports=["from app.service import execute"]),
                FileAnalysis("app/service.py", "python", 8, 1, functions=["execute"]),
                FileAnalysis("app/other.py", "python", 3, 1, functions=["other"]),
            ],
        )
        graph = build_dependency_graph(intel)
        return graph, build_file_profiles(graph, intel)

    def test_extract_stack_frames_supports_python_and_javascript_formats(self):
        frames = extract_stack_frames('File "app/main.py", line 7, in run\n    at execute (app/service.js:12:3)')
        self.assertEqual(
            [
                IncidentFrame("app/main.py", 7, "run"),
                IncidentFrame("app/service.js", 12, "execute"),
            ],
            frames,
        )
        self.assertEqual(
            {"path": "app/main.py", "line": 7, "function": "run"},
            frames[0].to_dict(),
        )

    def test_extract_stack_frames_preserves_original_traceback_order(self):
        stack_trace = "\n".join([
            "    at bootstrap (app/entry.js:3:1)",
            '  File "app/main.py", line 21, in main',
            "    at execute (app/service.js:12:3)",
            '  File "app/other.py", line 9, in finish',
        ])
        frames = extract_stack_frames(stack_trace)
        self.assertEqual(
            [
                IncidentFrame("app/entry.js", 3, "bootstrap"),
                IncidentFrame("app/main.py", 21, "main"),
                IncidentFrame("app/service.js", 12, "execute"),
                IncidentFrame("app/other.py", 9, "finish"),
            ],
            frames,
        )

    def test_extract_stack_frames_handles_multiple_frames_from_same_file(self):
        stack_trace = "\n".join([
            "Traceback (most recent call last):",
            '  File "app/main.py", line 30, in main',
            "    run()",
            '  File "app/main.py", line 14, in run',
            "    items = list(map(lambda x: step(x), data))",
            '  File "app/main.py", line 14, in <lambda>',
            "    items = list(map(lambda x: step(x), data))",
            '  File "app/main.py", line 8, in step',
            "    return step(value - 1)",
            '  File "app/main.py", line 8, in step',
            "    raise RuntimeError('boom')",
            "RuntimeError: boom",
        ])
        frames = extract_stack_frames(stack_trace)
        self.assertEqual(
            [
                IncidentFrame("app/main.py", 30, "main"),
                IncidentFrame("app/main.py", 14, "run"),
                IncidentFrame("app/main.py", 14, "<lambda>"),
                IncidentFrame("app/main.py", 8, "step"),
                IncidentFrame("app/main.py", 8, "step"),
            ],
            frames,
        )

    def test_extract_stack_frames_ignores_ordinary_error_messages_and_code_snippets(self):
        stack_trace = "\n".join([
            "Traceback (most recent call last):",
            '  File "app/main.py", line 7, in run',
            '    raise RuntimeError("failed while reading app/other.py:99")',
            "RuntimeError: failed while reading app/other.py:99",
            "ValueError: invalid configuration in app/service.py:15:2",
            "Error: could not load app/client.js:42:8 during startup",
            'RuntimeError: File "app/fake.py", line 12, in not_a_frame',
        ])
        frames = extract_stack_frames(stack_trace)
        self.assertEqual([IncidentFrame("app/main.py", 7, "run")], frames)

    def test_extract_stack_frames_handles_malformed_and_incomplete_tracebacks(self):
        self.assertEqual([], extract_stack_frames(""))
        self.assertEqual([], extract_stack_frames("Traceback (most recent call last):\nRuntimeError: boom"))

        incomplete_and_malformed = "\n".join([
            "Traceback (most recent call last):",
            '  File "app/main.py", line 10, in main',
            "    execute()",
            '  File "app/service.py", line 18',
            '  File "app/broken.py", line 0, in invalid_zero_line',
            '  File "app/broken.py", line -4, in invalid_negative_line',
            '  File "app/broken.py", line abc, in invalid_non_numeric',
            '  File "   ", line 12, in empty_path',
            '  File "app/truncated.py", line 15, in',
            '  File "app/truncated.py", line ',
            '  File "app/truncated.py"',
            "    at app/anon.js:24:5",
            "    at bad_js_frame (app/anon.js:0:1)",
            "    at incomplete_js_frame (app/anon.js:",
        ])
        frames = extract_stack_frames(incomplete_and_malformed)
        self.assertEqual(
            [
                IncidentFrame("app/main.py", 10, "main"),
                IncidentFrame("app/service.py", 18, ""),
                IncidentFrame("app/anon.js", 24, ""),
            ],
            frames,
        )

    def test_extract_stack_frames_supports_v8_aliases_async_and_multi_token_names(self):
        stack_trace = "\n".join([
            "Error: failure",
            "    at Object.execute [as run] (app/service.js:12:3)",
            "    at Object.get value [as value] (app/model.ts:28:9)",
            "    at new async Service (app/factory.mjs:44:1)",
            "    at async handleRequest (app/controller.cjs:19:7)",
        ])
        self.assertEqual(
            [
                IncidentFrame("app/service.js", 12, "Object.execute [as run]"),
                IncidentFrame("app/model.ts", 28, "Object.get value [as value]"),
                IncidentFrame("app/factory.mjs", 44, "Service"),
                IncidentFrame("app/controller.cjs", 19, "handleRequest"),
            ],
            extract_stack_frames(stack_trace),
        )

    def test_extract_stack_frames_supports_java_and_kotlin_frames_without_space_before_paren(self):
        stack_trace = "\n".join([
            "java.lang.IllegalStateException: broken",
            "    at com.example.service.Runner.execute(Runner.java:12)",
            "    at com.example.service.KotlinRunner.run(KotlinRunner.kt:34)",
        ])
        self.assertEqual(
            [
                IncidentFrame("Runner.java", 12, "com.example.service.Runner.execute"),
                IncidentFrame("KotlinRunner.kt", 34, "com.example.service.KotlinRunner.run"),
            ],
            extract_stack_frames(stack_trace),
        )

    def test_extract_stack_frames_supports_paths_with_spaces_parentheses_and_file_urls(self):
        stack_trace = "\n".join([
            "    at Page (app/(dashboard)/page.tsx:12:3)",
            "    at execute (/Users/dev/My App/src/service.ts:25:7)",
            "    at load (file:///app/src/loader.mjs:18:2)",
            "    at file:///Users/dev/My%20App/src/entry.js:9:1",
        ])
        self.assertEqual(
            [
                IncidentFrame("app/(dashboard)/page.tsx", 12, "Page"),
                IncidentFrame("/Users/dev/My App/src/service.ts", 25, "execute"),
                IncidentFrame("/app/src/loader.mjs", 18, "load"),
                IncidentFrame("/Users/dev/My App/src/entry.js", 9, ""),
            ],
            extract_stack_frames(stack_trace),
        )

    def test_extract_stack_frames_supports_go_ruby_php_rust_and_other_mapped_languages(self):
        stack_trace = "\n".join([
            "goroutine 1 [running]:",
            "github.com/acme/project/internal/pkg.(*Runner).Execute(0x1, 0x2)",
            "\t/workspace/internal/pkg/service.go:42 +0x85",
            "created by main.main in goroutine 1",
            "\t/workspace/main.go:19 +0x1c",
            "    from app/workers/job.rb:15:in `perform'",
            "    from app/workers/runner.rb:8:in 'run'",
            "#0 /var/www/app/Http/Controller.php(51): App\\Http\\Controller->index()",
            "thread 'main' panicked at src/main.rs:27:5:",
            "   0: crate::engine::process",
            "             at src/engine.rs:88:13",
            "    at App.Program.Main (src/Program.cs:16:4)",
            "    at NativeRunner (src/native/worker.cpp:64:2)",
            "    at ScalaService.run(ScalaService.scala:31)",
            "    at SwiftHandler.handle (Sources/App/Handler.swift:22:1)",
            "    at lua_entry (scripts/handler.lua:11:1)",
        ])
        self.assertEqual(
            [
                IncidentFrame("/workspace/internal/pkg/service.go", 42, "github.com/acme/project/internal/pkg.(*Runner).Execute"),
                IncidentFrame("/workspace/main.go", 19, "main.main"),
                IncidentFrame("app/workers/job.rb", 15, "perform"),
                IncidentFrame("app/workers/runner.rb", 8, "run"),
                IncidentFrame("/var/www/app/Http/Controller.php", 51, "App\\Http\\Controller->index"),
                IncidentFrame("src/main.rs", 27, ""),
                IncidentFrame("src/engine.rs", 88, "crate::engine::process"),
                IncidentFrame("src/Program.cs", 16, "App.Program.Main"),
                IncidentFrame("src/native/worker.cpp", 64, "NativeRunner"),
                IncidentFrame("ScalaService.scala", 31, "ScalaService.run"),
                IncidentFrame("Sources/App/Handler.swift", 22, "SwiftHandler.handle"),
                IncidentFrame("scripts/handler.lua", 11, "lua_entry"),
            ],
            extract_stack_frames(stack_trace),
        )

    def test_extract_stack_frames_prevents_cross_language_pending_function_leakage(self):
        stack_trace = "\n".join([
            '  File "app/main.py", line 10, in main',
            "    execute()",
            "    at app/anon.js:24:5",
            "   0: crate::engine::process",
            "    at app/other_anon.js:31:2",
            "   1: crate::engine::orphan",
            "\t/workspace/main.go:19 +0x1c",
            "main.goFunc(0x1)",
            "             at src/engine.rs:88:13",
        ])
        self.assertEqual(
            [
                IncidentFrame("app/main.py", 10, "main"),
                IncidentFrame("app/anon.js", 24, ""),
                IncidentFrame("app/other_anon.js", 31, ""),
                IncidentFrame("/workspace/main.go", 19, ""),
                IncidentFrame("src/engine.rs", 88, ""),
            ],
            extract_stack_frames(stack_trace),
        )

    def test_extract_stack_frames_supports_go_generics_and_legacy_created_by(self):
        stack_trace = "\n".join([
            "goroutine 18 [running]:",
            "main.Run[int](0x1)",
            "\t/app/main.go:10 +0x10",
            "pkg.(*Cache[string, int]).Get(0x2)",
            "\t/app/cache.go:44 +0x28",
            "created by main.spawn",
            "\t/app/main.go:20 +0x12",
        ])
        self.assertEqual(
            [
                IncidentFrame("/app/main.go", 10, "main.Run[int]"),
                IncidentFrame("/app/cache.go", 44, "pkg.(*Cache[string, int]).Get"),
                IncidentFrame("/app/main.go", 20, "main.spawn"),
            ],
            extract_stack_frames(stack_trace),
        )

    def test_extract_stack_frames_supports_rust_trait_impl_and_closure_symbols(self):
        stack_trace = "\n".join([
            "   0: <app::Service as app::Runner>::run::{{closure}}",
            "             at src/lib.rs:42:9",
            "   1: 0x55555555 - <core::future::GenFuture<T> as core::future::Future>::poll",
            "             at src/future.rs:15:3",
        ])
        self.assertEqual(
            [
                IncidentFrame("src/lib.rs", 42, "<app::Service as app::Runner>::run::{{closure}}"),
                IncidentFrame("src/future.rs", 15, "<core::future::GenFuture<T> as core::future::Future>::poll"),
            ],
            extract_stack_frames(stack_trace),
        )

    def test_extract_stack_frames_ignores_non_runtime_data_and_markup_extensions(self):
        stack_trace = "\n".join([
            "    at config.json:10:2",
            "    at settings.yaml:5:1",
            "    at rules.yml:8:3",
            "    at pyproject.toml:14:1",
            "    at index.html:22:4",
            "    at styles.css:9:1",
            '  File "app/main.py", line 7, in run',
        ])
        self.assertEqual(
            [IncidentFrame("app/main.py", 7, "run")],
            extract_stack_frames(stack_trace),
        )

    def test_context_prioritizes_stack_frames_and_graph_neighbors(self):
        with tempfile.TemporaryDirectory() as repo_root:
            os.makedirs(os.path.join(repo_root, "app"))
            with open(os.path.join(repo_root, "app", "main.py"), "w", encoding="utf-8") as handle:
                handle.write("\n".join(["value = 1"] * 12))
            graph, profiles = self._graph_and_profiles(repo_root)
            incident = Incident("inc-1", "execute failed", 'File "app/main.py", line 7, in run', "RuntimeError")

            context = build_repair_context(incident, graph, profiles, repo_root)

            self.assertEqual("app/main.py", context.evidence[0].path)
            self.assertIn("app/service.py", [item.path for item in context.evidence])
            self.assertIn("7: value = 1", context.evidence[0].excerpt)
            self.assertEqual([], context.unmapped_frames)

    def test_load_incident_validates_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "incident.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"id": "inc-2", "error": "broken", "stack": ["line one"]}, handle)
            incident = load_incident(path)
            self.assertEqual("inc-2", incident.incident_id)
            self.assertEqual("broken", incident.message)
            self.assertEqual("line one", incident.stack_trace)

    def test_match_repository_path_resolves_valid_exact_and_source_root_paths(self):
        with tempfile.TemporaryDirectory() as parent_dir:
            repo_root = os.path.join(parent_dir, "click")
            os.makedirs(repo_root)
            available = {
                "main.py",
                "app/main.py",
                ".github/scripts/ci.py",
                "src/click/core.py",
                "pkg/server/handler.go",
                "vendor/internal/helper.py",
                "services/api/pkg/auth/token.go",
            }
            self.assertEqual("main.py", _match_repository_path("main.py", repo_root, available))
            self.assertEqual("app/main.py", _match_repository_path("app/main.py", repo_root, available))
            self.assertEqual("app/main.py", _match_repository_path("./app/main.py", repo_root, available))
            self.assertEqual("app/main.py", _match_repository_path(r"app\main.py", repo_root, available))
            self.assertEqual(
                ".github/scripts/ci.py",
                _match_repository_path(".github/scripts/ci.py", repo_root, available),
            )
            self.assertEqual(
                "app/main.py",
                _match_repository_path("click/app/main.py", repo_root, available),
            )
            self.assertEqual(
                "src/click/core.py",
                _match_repository_path("click/core.py", repo_root, available),
            )
            self.assertEqual(
                "pkg/server/handler.go",
                _match_repository_path("pkg/server/handler.go", repo_root, available),
            )
            self.assertEqual(
                "vendor/internal/helper.py",
                _match_repository_path("vendor/internal/helper.py", repo_root, available),
            )
            self.assertEqual(
                "services/api/pkg/auth/token.go",
                _match_repository_path("pkg/auth/token.go", repo_root, available),
            )

    def test_match_repository_path_enforces_physical_symlink_containment(self):
        with tempfile.TemporaryDirectory() as sandbox:
            repo_root = os.path.join(sandbox, "repo")
            outside_dir = os.path.join(sandbox, "outside")
            os.makedirs(os.path.join(repo_root, "app"))
            os.makedirs(outside_dir)

            real_file = os.path.join(repo_root, "app", "main.py")
            with open(real_file, "w", encoding="utf-8") as handle:
                handle.write("x = 1\n")

            internal_link = os.path.join(repo_root, "app", "internal_link.py")
            os.symlink(real_file, internal_link)

            outside_file = os.path.join(outside_dir, "secret.py")
            with open(outside_file, "w", encoding="utf-8") as handle:
                handle.write("secret = 1\n")

            escaping_link = os.path.join(repo_root, "app", "escape.py")
            os.symlink(outside_file, escaping_link)

            broken_escaping_link = os.path.join(repo_root, "app", "broken_escape.py")
            os.symlink(os.path.join(outside_dir, "nonexistent.py"), broken_escaping_link)

            symlink_repo_root = os.path.join(sandbox, "repo_alias")
            os.symlink(repo_root, symlink_repo_root)

            available = {
                "app/main.py",
                "app/internal_link.py",
                "app/escape.py",
                "app/broken_escape.py",
            }

            self.assertEqual(
                "app/main.py",
                _match_repository_path(real_file, repo_root, available),
            )
            self.assertEqual(
                "app/main.py",
                _match_repository_path(f"file://{real_file}", repo_root, available),
            )
            self.assertEqual(
                "app/main.py",
                _match_repository_path(
                    os.path.join(symlink_repo_root, "app", "main.py"),
                    repo_root,
                    available,
                ),
            )
            self.assertEqual(
                "app/main.py",
                _match_repository_path(real_file, symlink_repo_root, {"app/main.py"}),
            )
            self.assertEqual(
                "app/internal_link.py",
                _match_repository_path(internal_link, repo_root, {"app/internal_link.py"}),
            )
            # Preserves link identity when both link and target are in available_paths,
            # including when repo_root or frame_path uses the symlinked repo alias
            self.assertEqual(
                "app/internal_link.py",
                _match_repository_path(internal_link, repo_root, available),
            )
            self.assertEqual(
                "app/internal_link.py",
                _match_repository_path(internal_link, symlink_repo_root, available),
            )
            self.assertEqual(
                "app/internal_link.py",
                _match_repository_path(
                    os.path.join(symlink_repo_root, "app", "internal_link.py"),
                    repo_root,
                    available,
                ),
            )
            # Repo-name prefix works for both lexical alias name and physical repo name
            self.assertEqual(
                "app/main.py",
                _match_repository_path("repo_alias/app/main.py", symlink_repo_root, available),
            )
            self.assertEqual(
                "app/main.py",
                _match_repository_path("repo/app/main.py", symlink_repo_root, available),
            )

            # Symlinks escaping repo_root must be rejected whether passed as absolute or relative
            self.assertIsNone(_match_repository_path(escaping_link, repo_root, available))
            self.assertIsNone(_match_repository_path(escaping_link, symlink_repo_root, available))
            self.assertIsNone(_match_repository_path("app/escape.py", repo_root, available))
            self.assertIsNone(_match_repository_path("app/escape.py", symlink_repo_root, available))
            self.assertIsNone(_match_repository_path(broken_escaping_link, repo_root, available))
            self.assertIsNone(_match_repository_path("app/broken_escape.py", repo_root, available))

    def test_match_repository_path_rejects_external_and_unrelated_paths(self):
        with tempfile.TemporaryDirectory() as repo_root:
            available = {"main.py", "app/main.py", "app/service.py", "index.js", "src/click/core.py"}

            # Relative external dependency and unrelated longer paths
            self.assertIsNone(
                _match_repository_path("site-packages/app/main.py", repo_root, available)
            )
            self.assertIsNone(
                _match_repository_path(".venv/lib/python3.12/site-packages/app/main.py", repo_root, available)
            )
            self.assertIsNone(
                _match_repository_path("node_modules/pkg/index.js", repo_root, available)
            )
            self.assertIsNone(
                _match_repository_path("vendor/acme/app/service.py", repo_root, available)
            )
            self.assertIsNone(
                _match_repository_path("pkg/mod/github.com/acme/lib@v1.0.0/app/main.py", repo_root, available)
            )
            self.assertIsNone(
                _match_repository_path("other_service/app/main.py", repo_root, available)
            )
            self.assertIsNone(
                _match_repository_path("external/main.py", repo_root, available)
            )
            self.assertIsNone(
                _match_repository_path("../app/main.py", repo_root, available)
            )

            # In-repo virtualenv or untracked absolute paths
            self.assertIsNone(
                _match_repository_path(
                    os.path.join(repo_root, ".venv", "lib", "python3.12", "site-packages", "app", "main.py"),
                    repo_root,
                    available,
                )
            )
            self.assertIsNone(
                _match_repository_path(
                    os.path.join(repo_root, "untracked", "main.py"),
                    repo_root,
                    available,
                )
            )

            # External POSIX and Windows absolute paths
            self.assertIsNone(
                _match_repository_path("/usr/lib/python3.12/site-packages/app/main.py", repo_root, available)
            )
            self.assertIsNone(
                _match_repository_path("/opt/other_repo/app/main.py", repo_root, available)
            )
            self.assertIsNone(
                _match_repository_path(r"C:\other_repo\app\main.py", repo_root, available)
            )
            self.assertIsNone(
                _match_repository_path("file:///C:/other_repo/app/main.py", repo_root, available)
            )
            self.assertIsNone(
                _match_repository_path(r"\Windows\System32\main.py", repo_root, available)
            )

    def test_match_repository_path_rejects_duplicate_filenames_ambiguous_suffixes_and_collisions(self):
        with tempfile.TemporaryDirectory() as repo_root:
            # Bare filename not at repository root
            self.assertIsNone(
                _match_repository_path("service.py", repo_root, {"app/service.py"})
            )
            self.assertIsNone(
                _match_repository_path("service.py", repo_root, {"app/service.py", "billing/service.py"})
            )

            # Ambiguous multi-segment suffix match
            self.assertIsNone(
                _match_repository_path(
                    "core/handler.py",
                    repo_root,
                    {"service_a/core/handler.py", "service_b/core/handler.py"},
                )
            )

            # Colliding normalized paths in available_paths must return None
            self.assertIsNone(
                _match_repository_path(
                    "app/main.py",
                    repo_root,
                    {"app/main.py", "./app/main.py"},
                )
            )
            self.assertIsNone(
                _match_repository_path(
                    "app/main.py",
                    repo_root,
                    {"app/main.py", r"app\main.py"},
                )
            )

    def test_match_repository_path_validates_jvm_package_qualified_frames(self):
        with tempfile.TemporaryDirectory() as repo_root:
            available = {
                "Main.java",
                "src/main/java/com/acme/Service.java",
                "src/main/java/com/acme/auth/Service.java",
                "src/main/java/com/acme/billing/Service.java",
                "src/main/kotlin/com/acme/auth.kt",
                "src/main/kotlin/com/acme/auth/Service.kt",
            }

            # Disambiguates duplicate Service.java via package prefix in frame_function
            self.assertEqual(
                "src/main/java/com/acme/auth/Service.java",
                _match_repository_path(
                    "Service.java",
                    repo_root,
                    available,
                    "com.acme.auth.Service.login",
                ),
            )
            self.assertEqual(
                "src/main/java/com/acme/billing/Service.java",
                _match_repository_path(
                    "Service.java",
                    repo_root,
                    available,
                    "com.acme.billing.Service.charge",
                ),
            )

            # Nested/anonymous classes ($-separated JVM binary class names)
            self.assertEqual(
                "src/main/java/com/acme/auth/Service.java",
                _match_repository_path(
                    "Service.java",
                    repo_root,
                    available,
                    "com.acme.auth.Service$Inner$1.run",
                ),
            )

            # Kotlin-generated class and synthetic method names
            self.assertEqual(
                "src/main/kotlin/com/acme/auth/Service.kt",
                _match_repository_path(
                    "Service.kt",
                    repo_root,
                    available,
                    "com.acme.auth.ServiceKt.login",
                ),
            )
            self.assertEqual(
                "src/main/kotlin/com/acme/auth/Service.kt",
                _match_repository_path(
                    "Service.kt",
                    repo_root,
                    available,
                    "com.acme.auth.ServiceKt$login$1.invokeSuspend",
                ),
            )
            self.assertEqual(
                "src/main/kotlin/com/acme/auth/Service.kt",
                _match_repository_path(
                    "Service.kt",
                    repo_root,
                    available,
                    "com.acme.auth.Service.login$default",
                ),
            )

            # Java 9+ module and classloader prefixes
            self.assertEqual(
                "src/main/java/com/acme/auth/Service.java",
                _match_repository_path(
                    "Service.java",
                    repo_root,
                    available,
                    "app//com.acme.auth.Service.login",
                ),
            )
            self.assertEqual(
                "src/main/java/com/acme/auth/Service.java",
                _match_repository_path(
                    "Service.java",
                    repo_root,
                    available,
                    "com.acme.auth@1.0/com.acme.auth.Service.login",
                ),
            )
            self.assertEqual(
                "src/main/java/com/acme/auth/Service.java",
                _match_repository_path(
                    "Service.java",
                    repo_root,
                    available,
                    "loader/com.acme.auth@1.0/com.acme.auth.Service.login",
                ),
            )

            # Default-package class matches root Main.java, but never nested com/acme/Main.java
            self.assertEqual(
                "Main.java",
                _match_repository_path("Main.java", repo_root, available, "Main.main"),
            )
            self.assertIsNone(
                _match_repository_path(
                    "Main.java",
                    repo_root,
                    {"src/main/java/com/acme/Main.java"},
                    "Main.main",
                )
            )

            # External JVM packages, mismatched class stems, and malformed function names must return None
            self.assertIsNone(
                _match_repository_path(
                    "Service.java",
                    repo_root,
                    available,
                    "org.springframework.web.Service.login",
                )
            )
            self.assertIsNone(
                _match_repository_path(
                    "Service.java",
                    repo_root,
                    available,
                    "com.acme.auth.UnrelatedClass.login",
                )
            )
            # Package/class-name collisions must not mistake a package component for the outer class
            self.assertIsNone(
                _match_repository_path(
                    "Service.java",
                    repo_root,
                    available,
                    "com.acme.Service.UnrelatedClass.login",
                )
            )
            self.assertIsNone(
                _match_repository_path(
                    "Service.java",
                    repo_root,
                    available,
                    "com.acme.auth.Service.Inner.run",
                )
            )
            self.assertIsNone(
                _match_repository_path(
                    "auth.kt",
                    repo_root,
                    available,
                    "com.acme.auth.UnrelatedClassKt.login",
                )
            )
            for malformed_fn in (
                "com..acme.auth.Service.login",
                "com.acme.123bad.Service.login",
                "//com.acme.auth.Service.login",
                "..//com.acme.auth.Service.login",
                "---@/com.acme.auth.Service.login",
                "app..bad/com.acme.auth.Service.login",
                "a/b/c/com.acme.auth.Service.login",
                "com.acme.auth.Service.login with spaces",
                "../com/acme/auth/Service.login",
                "login",
                "",
            ):
                self.assertIsNone(
                    _match_repository_path("Service.java", repo_root, available, malformed_fn),
                    msg=f"Expected None for malformed function {malformed_fn!r}",
                )

    def test_build_repair_context_leaves_external_suffix_collisions_unmapped(self):
        with tempfile.TemporaryDirectory() as repo_root:
            os.makedirs(os.path.join(repo_root, "app"))
            with open(os.path.join(repo_root, "app", "main.py"), "w", encoding="utf-8") as handle:
                handle.write("\n".join(["value = 1"] * 12))
            graph, profiles = self._graph_and_profiles(repo_root)
            stack_trace = "\n".join([
                '  File ".venv/lib/python3.12/site-packages/app/service.py", line 4, in external_call',
                '  File "app/main.py", line 7, in run',
            ])
            incident = Incident("inc-ext", "execute failed", stack_trace, "RuntimeError")

            context = build_repair_context(incident, graph, profiles, repo_root)

            self.assertEqual("app/main.py", context.evidence[0].path)
            service_evidence = next(item for item in context.evidence if item.path == "app/service.py")
            self.assertEqual([], service_evidence.frame_lines)
            self.assertEqual(
                [IncidentFrame(".venv/lib/python3.12/site-packages/app/service.py", 4, "external_call")],
                context.unmapped_frames,
            )

    def test_build_repair_context_maps_jvm_frames_and_rejects_external_or_mismatched_classes(self):
        with tempfile.TemporaryDirectory() as repo_root:
            acme_java = "src/main/java/com/acme/Service.java"
            auth_java = "src/main/java/com/acme/auth/Service.java"
            billing_java = "src/main/java/com/acme/billing/Service.java"
            auth_kt = "src/main/kotlin/com/acme/auth/Service.kt"
            for rel_path in (acme_java, auth_java, billing_java, auth_kt):
                full_path = os.path.join(repo_root, *rel_path.split("/"))
                os.makedirs(os.path.dirname(full_path), exist_ok=True)
                with open(full_path, "w", encoding="utf-8") as handle:
                    handle.write("\n".join(["// line"] * 25))

            intel = RepoIntelligence(
                repo_path=repo_root,
                repo_url="",
                file_analyses=[
                    FileAnalysis(acme_java, "java", 25, 1, classes=["Service"], functions=["rootCall"]),
                    FileAnalysis(auth_java, "java", 25, 1, classes=["Service"], functions=["login"]),
                    FileAnalysis(billing_java, "java", 25, 1, classes=["Service"], functions=["charge"]),
                    FileAnalysis(auth_kt, "kotlin", 25, 1, functions=["login"]),
                ],
            )
            graph = build_dependency_graph(intel)
            profiles = build_file_profiles(graph, intel)

            stack_trace = "\n".join([
                "    at app//com.acme.auth.Service$Inner.login(Service.java:14)",
                "    at com.acme.auth.ServiceKt$login$1.invokeSuspend(Service.kt:9)",
                "    at org.springframework.web.Service.dispatch(Service.java:20)",
                "    at com.acme.auth.UnrelatedClass.helper(Service.java:18)",
                "    at com.acme.Service.UnrelatedClass.login(Service.java:22)",
                "    at ..//com.acme.billing.Service.charge(Service.java:11)",
            ])
            incident = Incident("inc-jvm", "auth failed", stack_trace, "IllegalStateException")

            context = build_repair_context(incident, graph, profiles, repo_root)

            evidence_by_path = {item.path: item for item in context.evidence}
            self.assertEqual([14], evidence_by_path[auth_java].frame_lines)
            self.assertEqual([9], evidence_by_path[auth_kt].frame_lines)
            self.assertNotIn(acme_java, evidence_by_path)
            self.assertNotIn(billing_java, evidence_by_path)
            self.assertEqual(
                [
                    IncidentFrame("Service.java", 20, "org.springframework.web.Service.dispatch"),
                    IncidentFrame("Service.java", 18, "com.acme.auth.UnrelatedClass.helper"),
                    IncidentFrame("Service.java", 22, "com.acme.Service.UnrelatedClass.login"),
                    IncidentFrame("Service.java", 11, "..//com.acme.billing.Service.charge"),
                ],
                context.unmapped_frames,
            )

    def test_build_repair_context_rejects_escaping_symlinks_and_supports_symlinked_repo_root(self):
        with tempfile.TemporaryDirectory() as sandbox:
            repo_root = os.path.join(sandbox, "repo")
            outside_dir = os.path.join(sandbox, "outside")
            os.makedirs(os.path.join(repo_root, "app"))
            os.makedirs(outside_dir)

            real_main = os.path.join(repo_root, "app", "main.py")
            with open(real_main, "w", encoding="utf-8") as handle:
                handle.write("\n".join(["value = 1"] * 12))

            outside_secret = os.path.join(outside_dir, "secret.py")
            with open(outside_secret, "w", encoding="utf-8") as handle:
                handle.write("secret = 42\n")

            escaping_service = os.path.join(repo_root, "app", "service.py")
            os.symlink(outside_secret, escaping_service)

            symlink_repo_root = os.path.join(sandbox, "repo_alias")
            os.symlink(repo_root, symlink_repo_root)

            graph, profiles = self._graph_and_profiles(symlink_repo_root)
            stack_trace = "\n".join([
                f'  File "{escaping_service}", line 1, in leaked',
                '  File "app/service.py", line 1, in leaked_rel',
                '  File "repo/app/main.py", line 7, in run',
            ])
            incident = Incident("inc-sym", "execute failed", stack_trace, "RuntimeError")

            context = build_repair_context(incident, graph, profiles, symlink_repo_root)

            evidence_by_path = {item.path: item for item in context.evidence}
            self.assertEqual([7], evidence_by_path["app/main.py"].frame_lines)
            self.assertEqual([], evidence_by_path["app/service.py"].frame_lines)
            self.assertEqual(
                [
                    IncidentFrame(escaping_service, 1, "leaked"),
                    IncidentFrame("app/service.py", 1, "leaked_rel"),
                ],
                context.unmapped_frames,
            )

    def test_build_repair_context_rejects_duplicate_filenames_ambiguous_suffixes_and_profile_collisions(self):
        with tempfile.TemporaryDirectory() as repo_root:
            for rel_path in (
                "app/main.py",
                "app/service.py",
                "billing/service.py",
                "svc_a/core/handler.py",
                "svc_b/core/handler.py",
                "app/collide.py",
            ):
                full_path = os.path.join(repo_root, *rel_path.split("/"))
                os.makedirs(os.path.dirname(full_path), exist_ok=True)
                with open(full_path, "w", encoding="utf-8") as handle:
                    handle.write("\n".join(["value = 1"] * 12))

            intel = RepoIntelligence(
                repo_path=repo_root,
                repo_url="",
                file_analyses=[
                    FileAnalysis("app/main.py", "python", 12, 1, functions=["run"]),
                    FileAnalysis("app/service.py", "python", 12, 1, functions=["execute"]),
                    FileAnalysis("billing/service.py", "python", 12, 1, functions=["execute"]),
                    FileAnalysis("svc_a/core/handler.py", "python", 12, 1, functions=["handle"]),
                    FileAnalysis("svc_b/core/handler.py", "python", 12, 1, functions=["handle"]),
                    FileAnalysis("app/collide.py", "python", 12, 1, functions=["clash"]),
                ],
            )
            graph = build_dependency_graph(intel)
            profiles = build_file_profiles(graph, intel)
            profiles["./app/collide.py"] = profiles["app/collide.py"]

            stack_trace = "\n".join([
                '  File "service.py", line 3, in execute',
                '  File "core/handler.py", line 5, in handle',
                '  File "app/collide.py", line 6, in clash',
                '  File "app/main.py", line 7, in run',
            ])
            incident = Incident("inc-ambig", "failure", stack_trace, "RuntimeError")

            context = build_repair_context(incident, graph, profiles, repo_root)

            self.assertEqual([ "app/main.py" ], [item.path for item in context.evidence if item.frame_lines])
            self.assertEqual([7], context.evidence[0].frame_lines)
            self.assertEqual(
                [
                    IncidentFrame("service.py", 3, "execute"),
                    IncidentFrame("core/handler.py", 5, "handle"),
                    IncidentFrame("app/collide.py", 6, "clash"),
                ],
                context.unmapped_frames,
            )


if __name__ == "__main__":
    unittest.main()
