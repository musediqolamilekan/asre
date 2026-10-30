import json
import os
import tempfile
import unittest
import warnings
from unittest import mock

import intelligence.resolver as resolver_module
from intelligence.resolver import resolve_go_imports, resolve_imports, resolve_imports_detailed, resolve_js_imports, resolve_rust_imports


class TestTSConfigResolver(unittest.TestCase):
    def test_resolve_js_imports_uses_tsconfig_paths_aliases(self):
        with tempfile.TemporaryDirectory() as repo_root:
            os.makedirs(os.path.join(repo_root, "src", "utils"), exist_ok=True)
            os.makedirs(os.path.join(repo_root, "app"), exist_ok=True)

            with open(os.path.join(repo_root, "src", "utils", "math.ts"), "w", encoding="utf-8") as f:
                f.write("export const add = (a, b) => a + b;\n")

            with open(os.path.join(repo_root, "src", "main.ts"), "w", encoding="utf-8") as f:
                f.write("import { add } from '@/utils/math';\n")

            with open(os.path.join(repo_root, "app", "config.ts"), "w", encoding="utf-8") as f:
                f.write("export const mode = 'test';\n")

            tsconfig = {
                "compilerOptions": {
                    "baseUrl": ".",
                    "paths": {
                        "@/*": ["src/*"],
                        "~/*": ["app/*"],
                    },
                    "moduleResolution": "bundler",
                    "rootDirs": ["src", "app"],
                    "moduleSuffixes": [".ios", ".android", ".ts", ".tsx"],
                }
            }
            with open(os.path.join(repo_root, "tsconfig.json"), "w", encoding="utf-8") as f:
                json.dump(tsconfig, f)

            all_files = {
                os.path.join(repo_root, "src", "main.ts"),
                os.path.join(repo_root, "src", "utils", "math.ts"),
                os.path.join(repo_root, "app", "config.ts"),
            }

            resolved = resolve_js_imports(
                raw_import_src="import { add } from '@/utils/math';\n",
                current_file=os.path.join(repo_root, "src", "main.ts"),
                all_files=all_files,
                repo_root=repo_root,
            )

            expected_rel = os.path.join("src", "utils", "math.ts")
            expected_abs = os.path.join(repo_root, expected_rel)
            self.assertTrue(
                any(os.path.normpath(p) in {expected_rel, expected_abs} for p in resolved),
                f"Expected {expected_rel} or {expected_abs}, got {resolved}",
            )

    def test_resolve_js_imports_uses_extended_tsconfig_and_monorepo_layout(self):
        with tempfile.TemporaryDirectory() as repo_root:
            os.makedirs(os.path.join(repo_root, "packages", "web", "src", "utils"), exist_ok=True)
            os.makedirs(os.path.join(repo_root, "packages", "shared", "src"), exist_ok=True)

            with open(os.path.join(repo_root, "packages", "shared", "src", "math.ts"), "w", encoding="utf-8") as f:
                f.write("export const add = (a, b) => a + b;\n")

            with open(os.path.join(repo_root, "packages", "web", "src", "main.ts"), "w", encoding="utf-8") as f:
                f.write("import { add } from '@shared/math';\n")

            with open(os.path.join(repo_root, "tsconfig.base.json"), "w", encoding="utf-8") as f:
                json.dump({
                    "compilerOptions": {
                        "baseUrl": ".",
                        "paths": {
                            "@shared/*": ["packages/shared/src/*"],
                        },
                    }
                }, f)

            with open(os.path.join(repo_root, "packages", "web", "tsconfig.json"), "w", encoding="utf-8") as f:
                json.dump({
                    "extends": "../../tsconfig.base.json",
                    "compilerOptions": {
                        "baseUrl": ".",
                        "paths": {
                            "@shared/*": ["../shared/src/*"],
                        }
                    }
                }, f)

            all_files = {
                os.path.join(repo_root, "packages", "web", "src", "main.ts"),
                os.path.join(repo_root, "packages", "shared", "src", "math.ts"),
                os.path.join(repo_root, "tsconfig.base.json"),
                os.path.join(repo_root, "packages", "web", "tsconfig.json"),
            }

            resolved = resolve_js_imports(
                raw_import_src="import { add } from '@shared/math';\n",
                current_file=os.path.join(repo_root, "packages", "web", "src", "main.ts"),
                all_files=all_files,
                repo_root=repo_root,
            )

            expected_rel = os.path.join("packages", "shared", "src", "math.ts")
            expected_abs = os.path.join(repo_root, expected_rel)
            self.assertTrue(
                any(os.path.normpath(p) in {expected_rel, expected_abs} for p in resolved),
                f"Expected {expected_rel} or {expected_abs}, got {resolved}",
            )

    def test_resolve_js_imports_skips_bare_package_names(self):
        with tempfile.TemporaryDirectory() as repo_root:
            os.makedirs(os.path.join(repo_root, "src"), exist_ok=True)
            with open(os.path.join(repo_root, "src", "utils.ts"), "w", encoding="utf-8") as f:
                f.write("export const answer = 42;\n")

            all_files = {
                os.path.join(repo_root, "src", "utils.ts"),
            }

            resolved = resolve_js_imports(
                raw_import_src="import answer from 'utils';\n",
                current_file=os.path.join(repo_root, "src", "main.ts"),
                all_files=all_files,
                repo_root=repo_root,
            )

            self.assertEqual([], resolved)

    def test_resolve_imports_valid_python_import_still_resolves(self):
        with tempfile.TemporaryDirectory() as repo_root:
            pkg_dir = os.path.join(repo_root, "pkg")
            os.makedirs(pkg_dir, exist_ok=True)
            module_path = os.path.join(pkg_dir, "helper.py")
            main_path = os.path.join(pkg_dir, "main.py")

            with open(module_path, "w", encoding="utf-8") as f:
                f.write("VALUE = 42\n")
            with open(main_path, "w", encoding="utf-8") as f:
                f.write("import pkg.helper\n")

            all_files = {module_path, main_path}
            resolved = resolve_imports(
                language="python",
                raw_import_text="import pkg.helper\n",
                current_file=main_path,
                all_files=all_files,
                repo_root=repo_root,
            )

            self.assertIn(module_path, resolved)

    def test_resolve_imports_distinguishes_missing_from_internal_error(self):
        with tempfile.TemporaryDirectory() as repo_root:
            current_file = os.path.join(repo_root, "pkg", "main.py")
            os.makedirs(os.path.dirname(current_file), exist_ok=True)
            with open(current_file, "w", encoding="utf-8") as f:
                f.write("import missing\n")

            unresolved = resolve_imports(
                language="python",
                raw_import_text="import missing\n",
                current_file=current_file,
                all_files={current_file},
                repo_root=repo_root,
            )
            self.assertEqual([], unresolved)

            with mock.patch.dict(resolver_module._RESOLVERS, {"python": mock.Mock(side_effect=RuntimeError("boom"))}):
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter("always")
                    resolved = resolve_imports(
                        language="python",
                        raw_import_text="import x\n",
                        current_file=current_file,
                        all_files={current_file},
                        repo_root=repo_root,
                    )
                    self.assertEqual([], resolved)
                    self.assertTrue(any("Internal resolver error" in str(w.message) for w in caught))

    def test_resolve_imports_raises_when_requested_and_detailed_reports_error(self):
        with mock.patch.dict(resolver_module._RESOLVERS, {"python": mock.Mock(side_effect=RuntimeError("boom"))}):
            with self.assertRaises(RuntimeError):
                resolve_imports(
                    language="python",
                    raw_import_text="import x\n",
                    current_file="/tmp/main.py",
                    all_files={"/tmp/main.py"},
                    repo_root="/tmp",
                    raise_on_error=True,
                )

            results = resolve_imports_detailed(
                language="python",
                raw_import_text="import x\n",
                current_file="/tmp/main.py",
                all_files={"/tmp/main.py"},
                repo_root="/tmp",
            )

            self.assertEqual(1, len(results))
            self.assertEqual("error", results[0].status)
            self.assertIn("resolver error", results[0].reason)

    def test_resolve_go_imports_uses_module_path_and_ignores_external_suffix_matches(self):
        with tempfile.TemporaryDirectory() as repo_root:
            with open(os.path.join(repo_root, "go.mod"), "w", encoding="utf-8") as f:
                f.write("module github.com/acme/project\n\ngo 1.22\n")

            os.makedirs(os.path.join(repo_root, "internal", "pkg"), exist_ok=True)
            os.makedirs(os.path.join(repo_root, "vendor", "pkg"), exist_ok=True)

            local_pkg = os.path.join(repo_root, "internal", "pkg", "service.go")
            vendor_pkg = os.path.join(repo_root, "vendor", "pkg", "service.go")
            main_path = os.path.join(repo_root, "main.go")

            for path in (local_pkg, vendor_pkg, main_path):
                with open(path, "w", encoding="utf-8") as f:
                    f.write("package main\n")

            all_files = {
                "main.go",
                os.path.join("internal", "pkg", "service.go"),
                os.path.join("vendor", "pkg", "service.go"),
            }

            local_resolved = resolve_go_imports(
                raw_import_src='import "github.com/acme/project/internal/pkg"\n',
                current_file="main.go",
                all_files=all_files,
                repo_root=repo_root,
            )
            self.assertEqual([os.path.join("internal", "pkg", "service.go")], local_resolved)

            external_resolved = resolve_go_imports(
                raw_import_src='import "example.com/other/internal/pkg"\n',
                current_file="main.go",
                all_files=all_files,
                repo_root=repo_root,
            )
            self.assertEqual([], external_resolved)

            stdlib_resolved = resolve_go_imports(
                raw_import_src='import "fmt"\nimport "github.com/acme/project/missing"\n',
                current_file="main.go",
                all_files=all_files,
                repo_root=repo_root,
            )
            self.assertEqual([], stdlib_resolved)

    def test_resolve_go_imports_rejects_suffix_matches_and_missing_module_paths(self):
        with tempfile.TemporaryDirectory() as repo_root:
            with open(os.path.join(repo_root, "go.mod"), "w", encoding="utf-8") as f:
                f.write("module github.com/acme/project\n\ngo 1.22\n")

            os.makedirs(os.path.join(repo_root, "internal", "pkg"), exist_ok=True)
            os.makedirs(os.path.join(repo_root, "internal", "pkgv2"), exist_ok=True)
            os.makedirs(os.path.join(repo_root, "vendor", "pkg"), exist_ok=True)
            os.makedirs(os.path.join(repo_root, "other", "internal", "pkg"), exist_ok=True)

            local_pkg = os.path.join(repo_root, "internal", "pkg", "service.go")
            similar_pkg = os.path.join(repo_root, "internal", "pkgv2", "service.go")
            vendor_pkg = os.path.join(repo_root, "vendor", "pkg", "service.go")
            external_suffix_pkg = os.path.join(repo_root, "other", "internal", "pkg", "service.go")
            main_path = os.path.join(repo_root, "main.go")

            for path in (local_pkg, similar_pkg, vendor_pkg, external_suffix_pkg, main_path):
                with open(path, "w", encoding="utf-8") as f:
                    f.write("package main\n")

            all_files = {
                os.path.relpath(main_path, repo_root),
                os.path.join("internal", "pkg", "service.go"),
                os.path.join("internal", "pkgv2", "service.go"),
                os.path.join("vendor", "pkg", "service.go"),
                os.path.join("other", "internal", "pkg", "service.go"),
            }

            cases = [
                ("github.com/acme/project/internal/pkg", [os.path.join("internal", "pkg", "service.go")]),
                ("github.com/acme/project/vendor/pkg", [os.path.join("vendor", "pkg", "service.go")]),
                ("example.com/other/internal/pkg", []),
                ("example.com/other/vendor/pkg", []),
                ("fmt", []),
                ("github.com/acme/project/missing", []),
            ]

            for spec, expected in cases:
                actual = resolve_go_imports(
                    raw_import_src=f'import "{spec}"\n',
                    current_file=main_path,
                    all_files=all_files,
                    repo_root=repo_root,
                )
                self.assertEqual(expected, actual, f"Go import resolution mismatch for {spec}: expected {expected}, got {actual}")

    def test_resolve_go_imports_avoids_repo_wide_root_matches(self):
        with tempfile.TemporaryDirectory() as repo_root:
            with open(os.path.join(repo_root, "go.mod"), "w", encoding="utf-8") as f:
                f.write("module github.com/acme/project\n\ngo 1.22\n")

            os.makedirs(os.path.join(repo_root, "internal", "pkg"), exist_ok=True)
            root_path = os.path.join(repo_root, "main.go")
            nested_path = os.path.join(repo_root, "internal", "pkg", "service.go")

            with open(root_path, "w", encoding="utf-8") as f:
                f.write("package main\n")
            with open(nested_path, "w", encoding="utf-8") as f:
                f.write("package pkg\n")

            all_files = {
                os.path.relpath(root_path, repo_root),
                os.path.join("internal", "pkg", "service.go"),
            }

            resolved = resolve_go_imports(
                raw_import_src='import "github.com/acme/project"\n',
                current_file="main.go",
                all_files=all_files,
                repo_root=repo_root,
            )
            self.assertEqual(["main.go"], resolved)

    def test_resolve_rust_module_declaration(self):
        with tempfile.TemporaryDirectory() as repo_root:
            os.makedirs(os.path.join(repo_root, "src"), exist_ok=True)
            config_path = os.path.join(repo_root, "src", "config.rs")
            main_path = os.path.join(repo_root, "src", "main.rs")
            with open(config_path, "w", encoding="utf-8") as f:
                f.write("pub struct Settings;\n")
            with open(main_path, "w", encoding="utf-8") as f:
                f.write("mod config;\n")

            resolved = resolve_rust_imports(
                raw_import_src="mod config;\n",
                current_file=main_path,
                all_files={config_path, main_path},
                repo_root=repo_root,
            )
            self.assertEqual([config_path], resolved)

    def test_resolve_rust_directory_module(self):
        with tempfile.TemporaryDirectory() as repo_root:
            os.makedirs(os.path.join(repo_root, "src", "config"), exist_ok=True)
            mod_path = os.path.join(repo_root, "src", "config", "mod.rs")
            main_path = os.path.join(repo_root, "src", "main.rs")
            with open(mod_path, "w", encoding="utf-8") as f:
                f.write("pub struct Settings;\n")
            with open(main_path, "w", encoding="utf-8") as f:
                f.write("mod config;\n")

            resolved = resolve_rust_imports(
                raw_import_src="mod config;\n",
                current_file=main_path,
                all_files={mod_path, main_path},
                repo_root=repo_root,
            )
            self.assertEqual([mod_path], resolved)

    def test_resolve_rust_crate_and_nested_use(self):
        with tempfile.TemporaryDirectory() as repo_root:
            os.makedirs(os.path.join(repo_root, "src", "config", "database"), exist_ok=True)
            config_path = os.path.join(repo_root, "src", "config.rs")
            nested_path = os.path.join(repo_root, "src", "config", "database", "mod.rs")
            main_path = os.path.join(repo_root, "src", "main.rs")
            with open(config_path, "w", encoding="utf-8") as f:
                f.write("pub mod database;\n")
            with open(nested_path, "w", encoding="utf-8") as f:
                f.write("pub struct Connection;\n")
            with open(main_path, "w", encoding="utf-8") as f:
                f.write("use crate::config::database::Connection;\n")

            resolved = resolve_rust_imports(
                raw_import_src="use crate::config::database::Connection;\n",
                current_file=main_path,
                all_files={config_path, nested_path, main_path},
                repo_root=repo_root,
            )
            self.assertIn(nested_path, resolved)

    def test_resolve_rust_relative_and_parent_modules(self):
        with tempfile.TemporaryDirectory() as repo_root:
            os.makedirs(os.path.join(repo_root, "src", "config", "database"), exist_ok=True)
            mod_path = os.path.join(repo_root, "src", "config", "database", "mod.rs")
            parent_path = os.path.join(repo_root, "src", "config", "mod.rs")
            current_path = os.path.join(repo_root, "src", "config", "database", "service.rs")
            with open(mod_path, "w", encoding="utf-8") as f:
                f.write("pub struct Connection;\n")
            with open(parent_path, "w", encoding="utf-8") as f:
                f.write("pub mod database;\n")
            with open(current_path, "w", encoding="utf-8") as f:
                f.write("use super::database::Connection;\nuse self::database::Connection;\n")

            resolved = resolve_rust_imports(
                raw_import_src="use super::database::Connection;\nuse self::database::Connection;\n",
                current_file=current_path,
                all_files={mod_path, parent_path, current_path},
                repo_root=repo_root,
            )
            self.assertIn(mod_path, resolved)

    def test_resolve_rust_external_crates_and_missing_modules(self):
        with tempfile.TemporaryDirectory() as repo_root:
            os.makedirs(os.path.join(repo_root, "src"), exist_ok=True)
            local_path = os.path.join(repo_root, "src", "config.rs")
            main_path = os.path.join(repo_root, "src", "main.rs")
            with open(local_path, "w", encoding="utf-8") as f:
                f.write("pub struct Settings;\n")
            with open(main_path, "w", encoding="utf-8") as f:
                f.write("use std::fmt;\nuse serde::Serialize;\nuse crate::config::Settings;\nuse crate::missing::Thing;\n")

            resolved = resolve_rust_imports(
                raw_import_src="use std::fmt;\nuse serde::Serialize;\nuse crate::config::Settings;\nuse crate::missing::Thing;\n",
                current_file=main_path,
                all_files={local_path, main_path},
                repo_root=repo_root,
            )
            self.assertEqual([local_path], resolved)


if __name__ == "__main__":
    unittest.main()
