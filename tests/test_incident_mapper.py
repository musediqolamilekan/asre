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


if __name__ == "__main__":
    unittest.main()
