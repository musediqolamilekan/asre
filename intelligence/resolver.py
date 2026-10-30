"""
Import Resolver  —  maps raw import statements → canonical repo-relative file paths.

Module resolution is implemented per-language with full awareness of:

  Python
    ├─ absolute:  from app.config import Settings  →  app/config.py
    │              import app.config                →  app/config.py
    ├─ relative:  from .config import Settings      →  <current_dir>/config.py
    │              from ..utils import helper        →  <parent_dir>/utils.py
    └─ source root discovery (src/, app/, backend/, …)

  JavaScript / TypeScript
    ├─ relative:  import { X } from "./models"      →  models.ts / models.tsx /
    │                                                   models.js / models/index.ts …
    ├─ aliases:   import X from "@/config"           →  src/config.ts …
    └─ bare (local-only):  resolved only if file exists in repo

  Go
    └─  "github.com/org/repo/internal/pkg"  →  internal/pkg/*.go

  C / C++
    └─  #include "relative/header.h"  →  path relative to current file

  Java / Kotlin
    └─  import com.example.model.User  →  com/example/model/User.java

Key guarantee:
  Given the same repo snapshot, resolve_imports() always returns the same
  set of paths (deterministic, reproducible).
"""

from __future__ import annotations

import json
import os
import re
import sys
import warnings
from dataclasses import dataclass
from typing import Optional

from .models import EcosystemContext


# ──────────────────────────────────────────────────────────────────────────────
# Regex patterns for extracting raw specifiers from import statement text
# ──────────────────────────────────────────────────────────────────────────────

# Python: captures the module path from all import styles
_PY_FROM    = re.compile(r"^from\s+(\.+[\w.]*|[\w][\w.]*)\s+import", re.MULTILINE)
_PY_IMPORT  = re.compile(r"^import\s+([\w][\w.]*(?:\s*,\s*[\w][\w.]*)*)", re.MULTILINE)

# JS/TS: import/export … from 'X', require('X'), import('X')
_JS_FROM    = re.compile(
    r"""(?:import|export)\s+(?:type\s+)?(?:[\s\S]*?\s+from\s+)?['"]([^'"]+)['"]""",
    re.MULTILINE,
)
_JS_REQUIRE = re.compile(r"""require\s*\(\s*['"]([^'"]+)['"]\s*\)""")
_JS_DYNAMIC = re.compile(r"""import\s*\(\s*['"]([^'"]+)['"]\s*\)""")

# Go
_GO_BLOCK   = re.compile(r'import\s*\(([^)]+)\)', re.DOTALL)
_GO_SINGLE  = re.compile(r'^import\s+(?:\w+\s+)?"([^"]+)"', re.MULTILINE)

# C / C++
_C_LOCAL    = re.compile(r'#\s*include\s+"([^"]+)"')

# Java / Kotlin
_JAVA       = re.compile(r'^import\s+(?:static\s+)?([\w][\w.]*)\s*;', re.MULTILINE)

# PHP: `use App\Http\Controllers\Controller;` (not function/const imports)
_PHP_USE    = re.compile(
    r"^use\s+(?!function\b)(?!const\b)(\\?[A-Za-z_][A-Za-z0-9_]*(?:\\[A-Za-z_][A-Za-z0-9_]*)*)(?:\s+as\s+[A-Za-z_][A-Za-z0-9_]*)?\s*;",
    re.MULTILINE,
)


# ──────────────────────────────────────────────────────────────────────────────
# Extension priority lists (most-specific first)
# ──────────────────────────────────────────────────────────────────────────────

JS_EXTENSIONS  = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]
PY_EXTENSIONS  = [".py"]
C_EXTENSIONS   = [".h", ".hpp", ".hxx", ".h++"]
JAVA_EXTENSIONS = [".java", ".kt"]


@dataclass(frozen=True)
class ImportResolution:
    """Outcome for one extracted import statement/specifier."""
    specifier: str
    status: str  # resolved, external, unresolved, ambiguous
    paths: tuple[str, ...] = ()
    reason: str = ""


def _import_specifiers(language: str, raw: str) -> list[str]:
    """Extract specifiers for reporting without changing legacy resolver APIs."""
    if language == "python":
        relative, absolute = _parse_python_specifiers(raw)
        return relative + absolute
    if language in {"javascript", "typescript", "tsx"}:
        return _parse_js_specifiers(raw)
    if language == "go":
        return _parse_go_specifiers(raw)
    if language in {"c", "cpp"}:
        return [m.group(1) for m in _C_LOCAL.finditer(raw)]
    if language in {"java", "kotlin"}:
        return [m.group(1) for m in _JAVA.finditer(raw)]
    if language == "rust":
        return [m.group(1) for m in _RUST_MOD.finditer(raw)] + [m.group(1) for m in _RUST_USE.finditer(raw)]
    if language == "php":
        return _parse_php_specifiers(raw)
    return [raw.strip()] if raw.strip() else []


def _invoke_resolver(
    resolver,
    statement: str,
    current_file: str,
    all_files: set[str],
    repo_root: str,
    ecosystem_context: Optional[EcosystemContext],
):
    return resolver(
        statement,
        current_file,
        all_files,
        repo_root,
        ecosystem_context=ecosystem_context,
    )


def resolve_imports_detailed(
    language: str,
    raw_import_text: str,
    current_file: str,
    all_files: set[str],
    repo_root: str,
    ecosystem_context: Optional[EcosystemContext] = None,
) -> list[ImportResolution]:
    """Resolve imports while retaining external and failed outcomes for callers."""
    specs = _import_specifiers(language, raw_import_text)
    if not specs:
        return []
    resolver = _RESOLVERS.get(language.lower())
    if resolver is None:
        return [ImportResolution(s, "unresolved", reason=f"unsupported language: {language}") for s in specs]
    results = []
    for spec in specs:
        if language == "python":
            statement = f"from {spec} import _" if spec.startswith(".") else f"import {spec}"
        elif language in {"javascript", "typescript", "tsx"}:
            statement = f"import '{spec}'"
        elif language == "go":
            statement = f'import "{spec}"'
        elif language in {"c", "cpp"}:
            statement = f'#include "{spec}"'
        elif language in {"java", "kotlin"}:
            statement = f"import {spec};"
        elif language == "rust":
            statement = f"mod {spec};" if re.fullmatch(r"\w+", spec) else f"use {spec};"
        elif language == "php":
            statement = f"use {spec};"
        else:
            statement = raw_import_text
        try:
            raw_paths = _invoke_resolver(
                resolver, statement, current_file, all_files, repo_root, ecosystem_context,
            )
            paths = []
            for path in raw_paths:
                normalized = os.path.normpath(path)
                if normalized != current_file and normalized in all_files and normalized not in paths:
                    paths.append(normalized)
        except Exception as exc:
            results.append(ImportResolution(spec, "error", reason=f"resolver error: {exc}"))
            continue
        if len(paths) == 1:
            results.append(ImportResolution(spec, "resolved", tuple(paths)))
            continue
        if len(paths) > 1:
            results.append(ImportResolution(spec, "ambiguous", tuple(paths), "multiple repository targets matched"))
            continue
        external = (
            (language == "python" and spec.split(".", 1)[0] in getattr(sys, "stdlib_module_names", set()))
            or (language in {"javascript", "typescript", "tsx"} and (spec.startswith("node:") or (not spec.startswith((".", "/", "@/", "~/", "#")) and "/" not in spec) or (spec.startswith("@") and not spec.startswith("@/"))))
            or (language in {"c", "cpp"} and spec not in all_files and "/" not in spec)
            or (language == "rust" and spec.split("::", 1)[0] in {"std", "core", "alloc"})
            or (language == "php" and not _php_matches_psr4(spec, ecosystem_context))
        )
        results.append(ImportResolution(spec, "external" if external else "unresolved",
                                         reason="classified as external dependency" if external else "no repository target found"))
    return results


# ──────────────────────────────────────────────────────────────────────────────
# Well-known top-level source directory names
# ──────────────────────────────────────────────────────────────────────────────

_COMMON_SRC_DIRS = {
    "src", "app", "backend", "frontend", "lib", "libs", "source",
    "pkg", "packages", "server", "api", "core", "internal",
}

# Common TypeScript / bundler path alias prefixes and what they usually mean
_TS_ALIASES = {
    "@/":  ["src/", "app/", ""],
    "~/":  ["src/", ""],
    "@":   ["src/", ""],
}


# ──────────────────────────────────────────────────────────────────────────────
# Utility helpers
# ──────────────────────────────────────────────────────────────────────────────

def _first_match(candidates: list[str], all_files: set[str], repo_root: str = "") -> Optional[str]:
    """Return the first path from `candidates` that exists in the repo file set."""
    for p in candidates:
        norm = os.path.normpath(p) if p else ""
        if norm in all_files:
            return norm

        if repo_root and not os.path.isabs(norm):
            abs_candidate = os.path.normpath(os.path.join(repo_root, norm))
            if abs_candidate in all_files:
                return abs_candidate

        if repo_root and os.path.isabs(norm):
            rel_candidate = os.path.relpath(norm, repo_root) if os.path.isdir(repo_root) or os.path.exists(repo_root) else norm
            if rel_candidate in all_files:
                return rel_candidate
    return None


def _all_matches(candidates: list[str], all_files: set[str], repo_root: str = "") -> list[str]:
    """Return every distinct existing candidate, preserving priority order."""
    matches: list[str] = []
    for candidate in candidates:
        hit = _first_match([candidate], all_files, repo_root)
        if hit and hit not in matches:
            matches.append(hit)
    return matches


def _norm(p: str) -> str:
    """Normalise a path to use os.sep and remove leading ./"""
    return os.path.normpath(p)


def _relative_candidates(base_dir: str, specifier: str, extensions: list[str]) -> list[str]:
    """
    Expand a relative specifier into candidate file paths.
    Tries: specifier itself, specifier + each ext, specifier/index + each ext.
    """
    raw = os.path.normpath(os.path.join(base_dir, specifier))
    candidates = [raw]
    for ext in extensions:
        candidates.append(raw + ext)
        candidates.append(os.path.join(raw, "index" + ext))
    return candidates


# ──────────────────────────────────────────────────────────────────────────────
# Source-root discovery
# ──────────────────────────────────────────────────────────────────────────────

def _discover_python_source_roots(all_files: set[str]) -> list[str]:
    """
    Discover directories that should act as Python source roots (sys.path entries).

    Algorithm:
      1. Collect all directories that contain an __init__.py  (= package dirs).
      2. A source root is the *parent* of any package dir whose parent is NOT
         itself a package dir (i.e., the root of a package tree).
      3. Also include well-known top-level source directory names.
      4. Always include the repo root ('').
    """
    pkg_dirs: set[str] = set()
    for f in all_files:
        if os.path.basename(f) == "__init__.py":
            d = os.path.dirname(f)
            if d:
                pkg_dirs.add(d)

    source_roots: set[str] = {""}  # repo root is always a source root

    for pkg_dir in pkg_dirs:
        parent = os.path.dirname(pkg_dir)
        # Parent is a source root when it is NOT itself a package
        if parent not in pkg_dirs:
            source_roots.add(parent)

    # Include any top-level directory with a well-known source name
    for f in all_files:
        parts = f.split(os.sep)
        if len(parts) > 1 and parts[0].lower() in _COMMON_SRC_DIRS:
            source_roots.add(parts[0])

    return sorted(source_roots)


def _discover_js_source_roots(all_files: set[str]) -> list[str]:
    """
    Discover JS/TS source roots by looking for package.json / tsconfig.json
    and by checking for well-known source directory names.
    """
    roots: set[str] = {""}  # always include repo root

    for f in all_files:
        parts = f.split(os.sep)
        name = parts[-1] if parts else ""
        if name in ("package.json", "tsconfig.json", "jsconfig.json"):
            # The directory containing these files is a source root candidate
            d = os.path.dirname(f)
            if d:
                roots.add(d)

    for f in all_files:
        parts = f.split(os.sep)
        if len(parts) > 1 and parts[0].lower() in _COMMON_SRC_DIRS:
            roots.add(parts[0])

    return sorted(roots)


# ──────────────────────────────────────────────────────────────────────────────
# Python resolver
# ──────────────────────────────────────────────────────────────────────────────

def _parse_python_specifiers(raw_import_src: str) -> tuple[list[str], list[str]]:
    """
    Extract (relative_specifiers, absolute_specifiers) from raw Python import text.

    Handles:
      from .config import Settings      → relative [".config"]
      from ..utils import helper        → relative ["..utils"]
      from app.config import Settings   → absolute ["app.config"]
      import app.config                 → absolute ["app.config"]
      import os, sys                    → absolute ["os", "sys"]
    """
    relatives: list[str] = []
    absolutes: list[str] = []

    for m in _PY_FROM.finditer(raw_import_src):
        spec = m.group(1)
        if spec.startswith("."):
            relatives.append(spec)
        else:
            absolutes.append(spec)

    for m in _PY_IMPORT.finditer(raw_import_src):
        for part in m.group(1).split(","):
            spec = part.strip()
            if spec:
                absolutes.append(spec)

    return relatives, absolutes


def _resolve_python_relative(
    spec: str,
    current_file: str,
    all_files: set[str],
) -> Optional[str]:
    """
    Resolve a relative Python import (starts with dots).

    from .config import X       →  <current_dir>/config.py
    from ..utils import X       →  <parent_dir>/utils.py
    from ...core.utils import X →  <grandparent_dir>/core/utils.py
    """
    # Count leading dots
    stripped = spec.lstrip(".")
    dots = len(spec) - len(stripped)

    # Start at the current file's directory
    base = os.path.dirname(current_file)

    # Each dot beyond the first moves up one directory
    for _ in range(dots - 1):
        base = os.path.dirname(base)
        if not base:
            base = ""

    # Convert module path to filesystem path
    if stripped:
        parts = stripped.split(".")
        relative_path = os.path.join(base, *parts) if base else os.path.join(*parts)
    else:
        # "from . import X" — imports from the package itself
        relative_path = base

    candidates = [
        relative_path + ".py",
        os.path.join(relative_path, "__init__.py"),
    ]
    return _first_match(candidates, all_files)


def _resolve_python_absolute(
    spec: str,
    all_files: set[str],
    source_roots: list[str],
    repo_root: str = "",
) -> list[str]:
    """
    Resolve an absolute Python import against all discovered source roots.

    from app.config import Settings → try:
      app/config.py
      app/config/__init__.py
      src/app/config.py
      src/app/config/__init__.py
      ...
    """
    # Skip stdlib and obviously external packages that have no '/' equivalent
    parts = spec.split(".")
    rel = os.path.join(*parts)  # e.g. "app/config"

    hits: list[str] = []
    for root in source_roots:
        base = os.path.join(root, rel) if root else rel
        candidates = [
            base + ".py",
            os.path.join(base, "__init__.py"),
        ]
        for candidate in candidates:
            hit = _first_match([candidate], all_files, repo_root)
            if hit and hit not in hits:
                hits.append(hit)
    return hits


def resolve_python_imports(
    raw_import_src: str,
    current_file: str,
    all_files: set[str],
    repo_root: str,
    ecosystem_context: Optional[EcosystemContext] = None,
) -> list[str]:
    """Resolve all Python imports in raw_import_src to repo-relative paths."""
    source_roots = _discover_python_source_roots(all_files)
    aliases = (ecosystem_context.python_path_aliases if ecosystem_context else {}) or {}
    extra_roots = [
        os.path.normpath(dest) for dest in aliases.values()
        if isinstance(dest, str) and dest
    ]
    combined_roots = list(dict.fromkeys(list(source_roots) + extra_roots))
    relatives, absolutes = _parse_python_specifiers(raw_import_src)

    resolved: list[str] = []

    for spec in relatives:
        hit = _resolve_python_relative(spec, current_file, all_files)
        if hit:
            resolved.append(hit)

    for spec in absolutes:
        resolved.extend(_resolve_python_absolute(spec, all_files, combined_roots, repo_root))
        for prefix, dest in aliases.items():
            if not isinstance(prefix, str) or not isinstance(dest, str):
                continue
            dotted = prefix.strip("/").replace("/", ".").strip(".")
            dest_root = dest.replace("\\", os.sep).rstrip(os.sep)
            if not dotted:
                continue
            if spec == dotted or spec.startswith(dotted + "."):
                remainder = spec[len(dotted):].lstrip(".")
                mapped = os.path.join(dest_root, *remainder.split(".")) if remainder else dest_root
                candidates = [mapped + ".py", os.path.join(mapped, "__init__.py")]
                for candidate in candidates:
                    hit = _first_match([candidate], all_files, repo_root)
                    if hit and hit not in resolved:
                        resolved.append(hit)

    return resolved


# ──────────────────────────────────────────────────────────────────────────────
# JavaScript / TypeScript resolver
# ──────────────────────────────────────────────────────────────────────────────

def _parse_js_specifiers(raw_import_src: str) -> list[str]:
    """Extract all import specifiers from raw JS/TS import statement text."""
    seen: set[str] = set()
    specs: list[str] = []
    for pattern in (_JS_FROM, _JS_REQUIRE, _JS_DYNAMIC):
        for m in pattern.finditer(raw_import_src):
            s = m.group(1).strip()
            if s and s not in seen:
                seen.add(s)
                specs.append(s)
    return specs


def _load_tsconfig_file(tsconfig_path: str) -> dict:
    """Load a tsconfig file and return its normalized data."""
    try:
        with open(tsconfig_path, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return {}


def _merge_tsconfig_data(base: dict, override: dict) -> dict:
    """Merge tsconfig data, with override taking precedence."""
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_tsconfig_data(merged[key], value)
        else:
            merged[key] = value
    return merged


def _resolve_tsconfig_path_value(value: str | list[str], base_dir: str) -> list[str]:
    """Normalize tsconfig path values relative to the tsconfig location."""
    if isinstance(value, str):
        values = [value]
    else:
        values = value or []

    result: list[str] = []
    for item in values:
        if not isinstance(item, str):
            continue
        normalized = item.replace("\\", "/")
        if normalized.startswith("./"):
            normalized = normalized[2:]
        result.append(os.path.normpath(os.path.join(base_dir, normalized)))
    return result


def _read_tsconfig_for_file(repo_root: str, current_file: str, all_files: set[str]) -> dict:
    """Read the nearest tsconfig.json applicable to the current file, including extends."""
    current_path = os.path.abspath(current_file) if os.path.isabs(current_file) else os.path.abspath(os.path.join(repo_root, current_file))
    current_dir = os.path.dirname(current_path)

    tsconfigs: list[str] = []
    for f in all_files:
        if os.path.basename(f) == "tsconfig.json":
            tsconfigs.append(f)

    best_match: tuple[int, str] | None = None
    for tsconfig in sorted(tsconfigs):
        tsconfig_path = tsconfig if os.path.isabs(tsconfig) else os.path.abspath(os.path.join(repo_root, tsconfig))
        tsconfig_dir = os.path.dirname(tsconfig_path)
        try:
            rel = os.path.relpath(current_dir, tsconfig_dir)
        except ValueError:
            continue

        if rel == ".." or rel.startswith(".." + os.sep) or rel == os.pardir:
            continue

        depth = len(rel.split(os.sep)) if rel not in ("", ".") else 0
        if best_match is None or depth < best_match[0]:
            best_match = (depth, tsconfig)

    if best_match is None:
        return {}

    tsconfig_rel = best_match[1]
    tsconfig_path = tsconfig_rel if os.path.isabs(tsconfig_rel) else os.path.join(repo_root, tsconfig_rel)
    config: dict = {}
    seen: set[str] = set()

    def load_config(path: str) -> dict:
        abs_path = os.path.abspath(path)
        if abs_path in seen:
            return {}
        seen.add(abs_path)
        data = _load_tsconfig_file(abs_path)
        inherited = data.get("extends")
        if inherited:
            parent = inherited
            if not os.path.isabs(parent):
                parent = os.path.join(os.path.dirname(abs_path), parent)
            parent_config = load_config(parent)
            data = _merge_tsconfig_data(parent_config, data)
        return data

    config = load_config(tsconfig_path)
    compiler_options = config.get("compilerOptions", {}) or {}

    tsconfig_dir_rel = os.path.dirname(tsconfig_rel)
    base_url = compiler_options.get("baseUrl") or "."
    base_url_rel = os.path.normpath(os.path.join(tsconfig_dir_rel, base_url)) if tsconfig_dir_rel else os.path.normpath(base_url)
    if base_url_rel == ".":
        base_url_rel = os.path.normpath(tsconfig_dir_rel or "")

    paths = compiler_options.get("paths", {}) or {}
    root_dirs = compiler_options.get("rootDirs", []) or []
    root_dirs = root_dirs if isinstance(root_dirs, list) else [root_dirs]
    root_dirs = [os.path.normpath(os.path.join(tsconfig_dir_rel, d)) if tsconfig_dir_rel and d not in (".", "") else os.path.normpath(d) for d in root_dirs]

    module_suffixes = compiler_options.get("moduleSuffixes", []) or []
    module_suffixes = module_suffixes if isinstance(module_suffixes, list) else [module_suffixes]

    return {
        "base_url": base_url,
        "base_url_rel": base_url_rel,
        "paths": paths,
        "root_dirs": root_dirs,
        "module_resolution": compiler_options.get("moduleResolution", ""),
        "module_suffixes": module_suffixes,
        "tsconfig_dir": tsconfig_dir_rel,
    }


def _expand_pattern_map(spec: str, mapping: dict[str, str], roots: list[str]) -> list[str]:
    """Expand a specifier against an alias → target map (tsconfig paths or package.json imports)."""
    candidates: list[str] = []
    for alias, value in mapping.items():
        if not isinstance(alias, str) or not isinstance(value, str):
            continue
        target_template = value.replace("\\", "/")
        if target_template.startswith("./"):
            target_template = target_template[2:]
        if alias.endswith("/*"):
            prefix = alias[:-1]
            if not spec.startswith(prefix):
                continue
            tail = spec[len(prefix):].lstrip("/")
            target = target_template.replace("*", tail)
        elif spec == alias:
            target = target_template.replace("*", "")
        else:
            continue
        for root in roots:
            root_prefix = root if root and root not in (".", "") else ""
            candidate = os.path.normpath(os.path.join(root_prefix, target)) if root_prefix else os.path.normpath(target)
            candidates.append(candidate)
            for ext in JS_EXTENSIONS:
                candidates.append(candidate + ext)
                candidates.append(os.path.join(candidate, "index" + ext))
    return candidates


def _expand_ts_alias(
    spec: str,
    js_roots: list[str],
    tsconfig_cfg: dict | None = None,
    subpath_imports: dict[str, str] | None = None,
) -> list[str]:
    """
    Try to resolve a TypeScript path alias (e.g. @/, ~/ or tsconfig paths entries) to candidate paths.
    Returns an empty list if the specifier doesn't look like a known alias.
    """
    alias_roots = list(js_roots)
    if tsconfig_cfg:
        base_root = tsconfig_cfg.get("base_url_rel", "")
        if base_root and base_root not in alias_roots:
            alias_roots.append(base_root)

    subpath_candidates = _expand_pattern_map(spec, subpath_imports or {}, [""])
    if subpath_candidates:
        return subpath_candidates

    if tsconfig_cfg:
        for alias, values in (tsconfig_cfg.get("paths", {}) or {}).items():
            entries = values if isinstance(values, list) else [values]
            if alias.endswith("/*"):
                prefix = alias[:-1]
                if spec.startswith(prefix):
                    tail = spec[len(prefix):].lstrip("/")
                    candidates: list[str] = []
                    for value in entries:
                        if not isinstance(value, str):
                            continue
                        target = value.replace("\\", "/").replace("*", tail)
                        for root in js_roots + [tsconfig_cfg.get("base_url_rel", "")]:
                            root_prefix = root if root and root not in (".", "") else ""
                            candidate = os.path.normpath(os.path.join(root_prefix, target)) if root_prefix else os.path.normpath(target)
                            candidates.append(candidate)
                            for ext in JS_EXTENSIONS:
                                candidates.append(candidate + ext)
                                candidates.append(os.path.join(candidate, "index" + ext))
                    return candidates
            elif spec == alias:
                for value in entries:
                    if not isinstance(value, str):
                        continue
                    target = value.replace("\\", "/")
                    candidates: list[str] = []
                    for root in js_roots + [tsconfig_cfg.get("base_url_rel", "")]:
                        root_prefix = root if root and root not in (".", "") else ""
                        candidate = os.path.normpath(os.path.join(root_prefix, target)) if root_prefix else os.path.normpath(target)
                        candidates.append(candidate)
                        for ext in JS_EXTENSIONS:
                            candidates.append(candidate + ext)
                            candidates.append(os.path.join(candidate, "index" + ext))
                    return candidates

    for alias, replacements in _TS_ALIASES.items():
        if spec.startswith(alias):
            tail = spec[len(alias):]
            candidates = []
            for rep in replacements:
                base = os.path.normpath(os.path.join(rep, tail)) if rep else os.path.normpath(tail)
                for ext in JS_EXTENSIONS:
                    candidates.append(base + ext)
                    candidates.append(os.path.join(base, "index" + ext))
            return candidates
    return []


def _looks_like_package_self_reference(spec: str) -> bool:
    """Package self-reference/imports syntax, e.g. #internal/config or #pkg/foo."""
    return spec.startswith("#")


def resolve_js_imports(
    raw_import_src: str,
    current_file: str,
    all_files: set[str],
    repo_root: str,
    ecosystem_context: Optional[EcosystemContext] = None,
) -> list[str]:
    """
    Resolve JS/TS imports.

    Handles:
      ./models             → models.ts / models.tsx / models.js / models/index.ts …
      ../utils             → ../utils.ts …
      @/components/Button  → src/components/Button.ts …
      ~/lib/utils          → src/lib/utils.ts …
      bare/module          → skip if clearly an npm package (not in repo)
    """
    specs = _parse_js_specifiers(raw_import_src)
    tsconfig_cfg = _read_tsconfig_for_file(repo_root, current_file, all_files)
    js_roots = _discover_js_source_roots(all_files)
    subpath_imports = (ecosystem_context.subpath_imports if ecosystem_context else {}) or {}

    if tsconfig_cfg:
        base_root = tsconfig_cfg.get("base_url_rel", "")
        if base_root and base_root not in js_roots:
            js_roots.append(base_root)
        for root_dir in tsconfig_cfg.get("root_dirs", []):
            norm = os.path.normpath(os.path.join(tsconfig_cfg.get("tsconfig_dir", ""), root_dir))
            if norm and norm not in js_roots:
                js_roots.append(norm)

    current_dir = os.path.dirname(current_file)
    resolved: list[str] = []

    for spec in specs:
        hits: list[str] = []

        if spec.startswith("."):
            # ── Relative import ──────────────────────────────────────
            candidates = _relative_candidates(current_dir, spec, JS_EXTENSIONS)
            hits = _all_matches(candidates, all_files)

        elif any(spec.startswith(alias.replace("*", "")) for alias in (list((tsconfig_cfg or {}).get("paths", {}).keys()) + list(subpath_imports.keys()) + list(_TS_ALIASES.keys()))) or _looks_like_package_self_reference(spec):
            alias_candidates = _expand_ts_alias(spec, js_roots, tsconfig_cfg, subpath_imports)
            hits = _all_matches(alias_candidates, all_files, repo_root)

        else:
            # Bare specifiers are ambiguous package names by default and are not
            # safe to interpret as repo-local modules without explicit config.
            if spec.startswith("node:"):
                continue
            if spec.startswith("#"):
                continue

            # Scoped packages like @scope/pkg are package imports, not repo-relative
            # file paths, unless a tsconfig alias explicitly matches them.
            if spec.startswith("@") and "/" in spec and not spec.startswith("@/"):
                continue

            # Bare names like lodash, react, utils are package imports in most JS
            # ecosystems; only path-like specifiers may be repo-local candidates.
            if "/" not in spec:
                continue

            for root in js_roots:
                base = os.path.join(root, spec) if root else spec
                candidates = [base]
                for ext in JS_EXTENSIONS:
                    candidates.append(base + ext)
                    candidates.append(os.path.join(base, "index" + ext))
                hits.extend(_all_matches(candidates, all_files, repo_root))
            hits = list(dict.fromkeys(hits))

        resolved.extend(hits)

    return resolved


# ──────────────────────────────────────────────────────────────────────────────
# Go resolver
# ──────────────────────────────────────────────────────────────────────────────

def _parse_go_specifiers(raw_import_src: str) -> list[str]:
    specs: list[str] = []
    for block in _GO_BLOCK.findall(raw_import_src):
        for line in block.splitlines():
            m = re.search(r'"([^"]+)"', line)
            if m:
                specs.append(m.group(1))
    for m in _GO_SINGLE.finditer(raw_import_src):
        specs.append(m.group(1))
    return specs


def _find_go_module_path(repo_root: str, current_file: str) -> tuple[str, str]:
    """Return the declared module path and its root directory from the nearest go.mod."""
    search_roots: list[str] = []
    if repo_root:
        search_roots.append(os.path.abspath(repo_root))
    if current_file:
        if os.path.isabs(current_file):
            current_abs = os.path.abspath(current_file)
        else:
            current_abs = os.path.abspath(os.path.join(repo_root, current_file))
        search_roots.append(os.path.dirname(current_abs))

    seen: set[str] = set()
    for start in search_roots:
        probe = start
        while True:
            if probe in seen:
                break
            seen.add(probe)
            mod_path = os.path.join(probe, "go.mod")
            if os.path.isfile(mod_path):
                with open(mod_path, "r", encoding="utf-8", errors="replace") as handle:
                    for line in handle:
                        match = re.match(r"^\s*module\s+([^\s]+)\s*$", line)
                        if match:
                            return match.group(1), probe
                return "", probe
            parent = os.path.dirname(probe)
            if parent == probe:
                break
            probe = parent

    return "", repo_root or ""


def resolve_go_imports(
    raw_import_src: str,
    current_file: str,
    all_files: set[str],
    repo_root: str,
    ecosystem_context: Optional[EcosystemContext] = None,
) -> list[str]:
    """
    Resolve Go imports using the local module declared in go.mod.

    Valid local imports such as "github.com/acme/project/internal/pkg" resolve
    to the package directory within this repo. External imports with matching
    suffixes are intentionally left unresolved unless they are part of the
    declared module path.
    """
    specs = _parse_go_specifiers(raw_import_src)
    resolved: list[str] = []
    module_path, module_root = _find_go_module_path(repo_root, current_file)

    for spec in specs:
        spec = spec.strip()
        if not spec or spec == "C":
            continue
        if "/" not in spec:
            continue

        if not module_path:
            continue

        if spec == module_path:
            candidate = module_root
            match_descendants = False
        elif spec.startswith(module_path + "/"):
            suffix = spec[len(module_path):].lstrip("/")
            candidate = os.path.join(module_root, *suffix.split("/")) if suffix else module_root
            match_descendants = True
        else:
            continue

        # Map the candidate back to repo-relative paths when the repo file-set is relative.
        if repo_root and os.path.isabs(candidate):
            candidate_rel = os.path.relpath(candidate, repo_root)
        else:
            candidate_rel = candidate

        candidate_abs = os.path.normpath(os.path.abspath(os.path.join(repo_root, candidate_rel))) if repo_root else os.path.normpath(candidate_rel)

        for f in sorted(all_files):
            norm_f = os.path.normpath(f)
            abs_f = os.path.normpath(os.path.abspath(os.path.join(repo_root, norm_f))) if repo_root else norm_f
            if not norm_f.endswith(".go"):
                continue

            if match_descendants:
                if norm_f == candidate_rel or norm_f.startswith(candidate_rel + os.sep) or abs_f == candidate_abs or abs_f.startswith(candidate_abs + os.sep):
                    resolved.append(f)
                continue

            # Module-root imports should only match files directly in the module root,
            # not every package recursively under that root.
            root_rel = candidate_rel if candidate_rel not in {"", "."} else ""
            current_dir = os.path.dirname(norm_f)
            if norm_f == candidate_rel or abs_f == candidate_abs or current_dir == root_rel:
                resolved.append(f)

    return list(dict.fromkeys(resolved))


# ──────────────────────────────────────────────────────────────────────────────
# C / C++ resolver
# ──────────────────────────────────────────────────────────────────────────────

def resolve_c_imports(
    raw_import_src: str,
    current_file: str,
    all_files: set[str],
    repo_root: str,
    ecosystem_context: Optional[EcosystemContext] = None,
) -> list[str]:
    """
    Resolve local #include directives.

    Only resolves #include "file.h" (double-quote form = local include).
    Skips #include <system_header.h> (angle-bracket = system header).

    Search order:
      1. Relative to current file's directory
      2. Relative to repo root
      3. Common include dirs: include/, src/, headers/
    """
    resolved: list[str] = []
    current_dir = os.path.dirname(current_file)
    search_dirs = [current_dir, ""]

    # Add top-level include directories
    for f in sorted(all_files):
        parts = f.split(os.sep)
        if len(parts) > 1 and parts[0].lower() in {"include", "includes", "headers", "inc"}:
            search_dirs.append(parts[0])

    for m in _C_LOCAL.finditer(raw_import_src):
        header = m.group(1)
        hit = None
        for search_dir in search_dirs:
            candidate = os.path.normpath(os.path.join(search_dir, header)) if search_dir else os.path.normpath(header)
            if candidate in all_files:
                hit = candidate
                break
        if hit:
            resolved.append(hit)

    return resolved


# ──────────────────────────────────────────────────────────────────────────────
# Java / Kotlin resolver
# ──────────────────────────────────────────────────────────────────────────────

def _find_java_source_roots(all_files: set[str]) -> list[str]:
    """
    Find Java source roots. Maven/Gradle standard layout:
      src/main/java/  and  src/test/java/
    Also accept flat layouts.
    """
    roots: set[str] = {""}
    for f in all_files:
        if f.endswith((".java", ".kt")):
            # Standard Maven layout
            norm = f.replace(os.sep, "/")
            for marker in ("/src/main/java/", "/src/test/java/", "/src/main/kotlin/", "/src/test/kotlin/"):
                idx = norm.find(marker)
                if idx >= 0:
                    root = f[: idx + len(marker)].rstrip("/")
                    roots.add(root.replace("/", os.sep))
    return sorted(roots)


def resolve_java_imports(
    raw_import_src: str,
    current_file: str,
    all_files: set[str],
    repo_root: str,
    ecosystem_context: Optional[EcosystemContext] = None,
) -> list[str]:
    """
    Resolve Java/Kotlin FQN imports.

    import com.example.model.User  →  com/example/model/User.java
    Also tries against discovered Maven source roots.
    """
    java_roots = _find_java_source_roots(all_files)
    resolved: list[str] = []

    for m in _JAVA.finditer(raw_import_src):
        fqn = m.group(1).strip()
        parts = fqn.split(".")
        rel = os.path.join(*parts)

        for root in java_roots:
            for ext in JAVA_EXTENSIONS:
                candidate = os.path.join(root, rel + ext) if root else rel + ext
                candidate = os.path.normpath(candidate)
                if candidate in all_files:
                    resolved.append(candidate)
                    break

    return resolved


# ──────────────────────────────────────────────────────────────────────────────
# Rust resolver  (best-effort; Rust's module system is complex)
# ──────────────────────────────────────────────────────────────────────────────

_RUST_USE = re.compile(r'^\s*use\s+([A-Za-z0-9_:{}]+)', re.MULTILINE)
_RUST_MOD = re.compile(r'^\s*mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;', re.MULTILINE)


def _rust_crate_root(current_file: str, repo_root: str) -> str:
    """Return the nearest directory containing a Cargo.toml, or repo_root as fallback."""
    if current_file:
        current_abs = os.path.abspath(current_file)
        current_dir = os.path.dirname(current_abs)
        probe = current_dir
        while True:
            if os.path.isfile(os.path.join(probe, "Cargo.toml")):
                return probe
            parent = os.path.dirname(probe)
            if parent == probe or (repo_root and os.path.abspath(repo_root) == os.path.abspath(probe)):
                break
            probe = parent
    if repo_root and os.path.isdir(repo_root):
        return os.path.abspath(repo_root)
    return os.path.dirname(os.path.abspath(current_file)) if current_file else repo_root


def _rust_module_base_dir(current_file: str, repo_root: str) -> str:
    """Start from the current module's directory, not an arbitrary search root."""
    if current_file:
        current_abs = os.path.abspath(current_file)
        current_dir = os.path.dirname(current_abs)
        if os.path.basename(current_abs) in {"main.rs", "lib.rs"}:
            return current_dir
        return current_dir
    return os.path.abspath(repo_root) if repo_root else os.getcwd()


def _resolve_rust_module_path(spec: str, current_file: str, repo_root: str, all_files: set[str]) -> list[str]:
    """Resolve a Rust module path to a local file using conventional rust module layouts."""
    if not spec or spec.startswith(("std::", "core::", "alloc::")):
        return []

    cleaned = spec.split(" as ", 1)[0].strip()
    if "{" in cleaned:
        cleaned = cleaned.split("{", 1)[0].strip()
    cleaned = cleaned.rstrip(":")
    if not cleaned or cleaned in {"self", "super", "crate"}:
        return []

    if cleaned.startswith("crate::"):
        base_dir = _rust_crate_root(current_file, repo_root)
        path = cleaned[len("crate::"):]
    elif cleaned.startswith("self::"):
        base_dir = _rust_module_base_dir(current_file, repo_root)
        path = cleaned[len("self::"):]
    elif cleaned.startswith("super::"):
        module_dir = _rust_module_base_dir(current_file, repo_root)
        parent_dir = os.path.dirname(module_dir)
        base_dir = parent_dir if parent_dir else module_dir
        path = cleaned[len("super::"):]
    else:
        base_dir = _rust_module_base_dir(current_file, repo_root)
        path = cleaned

    if not path:
        return []

    segments = [seg for seg in path.split("::") if seg and seg not in {"self", "super", "crate"}]
    if not segments:
        return []

    # Try the longest valid prefix first (module path before the symbol name).
    candidates: list[str] = []
    for idx in range(len(segments), 0, -1):
        prefix = segments[:idx]
        prefix_path = os.path.join(base_dir, *prefix)
        candidates.extend([
            prefix_path + ".rs",
            os.path.join(prefix_path, "mod.rs"),
            os.path.join(prefix_path, "main.rs"),
        ])

    # Also allow a crate-root/src style dir layout for crate-relative paths.
    if cleaned.startswith("crate::"):
        crate_root = _rust_crate_root(current_file, repo_root)
        src_root = os.path.join(crate_root, "src") if os.path.isdir(os.path.join(crate_root, "src")) else crate_root
        for idx in range(len(segments), 0, -1):
            prefix = segments[:idx]
            prefix_path = os.path.join(src_root, *prefix)
            candidates.extend([
                prefix_path + ".rs",
                os.path.join(prefix_path, "mod.rs"),
            ])

    hits: list[str] = []
    for candidate in candidates:
        normalized = os.path.normpath(candidate)
        if normalized in all_files and normalized not in hits:
            hits.append(normalized)
        elif not os.path.isabs(normalized):
            abs_candidate = os.path.normpath(os.path.join(repo_root, normalized)) if repo_root else normalized
            if abs_candidate in all_files and abs_candidate not in hits:
                hits.append(abs_candidate)
    return hits


def resolve_rust_imports(
    raw_import_src: str,
    current_file: str,
    all_files: set[str],
    repo_root: str,
    ecosystem_context: Optional[EcosystemContext] = None,
) -> list[str]:
    """
    Resolve Rust use/mod declarations.

    mod config; in src/main.rs  →  src/config.rs or src/config/mod.rs
    use crate::config::Settings → config.rs or config/mod.rs
    use self::foo::Bar or super::foo::Bar → current/parent module context
    """
    resolved: list[str] = []

    for m in _RUST_MOD.finditer(raw_import_src):
        mod_name = m.group(1)
        current_dir = os.path.dirname(os.path.abspath(current_file)) if current_file else os.path.abspath(repo_root)
        candidates = [
            os.path.join(current_dir, mod_name + ".rs"),
            os.path.join(current_dir, mod_name, "mod.rs"),
        ]
        hit = _first_match(candidates, all_files, repo_root)
        if hit:
            resolved.append(hit)

    for m in _RUST_USE.finditer(raw_import_src):
        spec = m.group(1).strip()
        if not spec:
            continue
        if spec.startswith(("std::", "core::", "alloc::")):
            continue
        # Ignore direct external crate imports such as serde::Serialize.
        if "::" in spec and not spec.startswith(("crate::", "self::", "super::")):
            first = spec.split("::", 1)[0]
            if first not in {"self", "super", "crate"}:
                # This is an external crate import unless it resolves to a local module.
                hits = _resolve_rust_module_path(spec, current_file, repo_root, all_files)
                if hits:
                    resolved.extend(hits)
                continue
        resolved.extend(_resolve_rust_module_path(spec, current_file, repo_root, all_files))

    return list(dict.fromkeys(resolved))


# ──────────────────────────────────────────────────────────────────────────────
# PHP resolver (Composer PSR-4)
# ──────────────────────────────────────────────────────────────────────────────

def _parse_php_specifiers(raw_import_src: str) -> list[str]:
    specs: list[str] = []
    seen: set[str] = set()
    for match in _PHP_USE.finditer(raw_import_src):
        fqn = match.group(1).lstrip("\\")
        if fqn and fqn not in seen:
            seen.add(fqn)
            specs.append(fqn)
    return specs


def _php_matches_psr4(spec: str, ecosystem_context: Optional[EcosystemContext]) -> bool:
    mappings = (ecosystem_context.psr4_mappings if ecosystem_context else {}) or {}
    fqn = spec.lstrip("\\")
    for namespace in mappings:
        prefix = namespace.replace("/", "\\").rstrip("\\")
        if not prefix:
            return True
        if fqn == prefix or fqn.startswith(prefix + "\\"):
            return True
    return False


def _php_candidates_for_fqn(fqn: str, namespace: str, destination: str) -> list[str]:
    prefix = namespace.replace("/", "\\").rstrip("\\")
    fqn = fqn.lstrip("\\")
    if prefix:
        if not (fqn == prefix or fqn.startswith(prefix + "\\")):
            return []
        remainder = fqn[len(prefix):].lstrip("\\")
    else:
        remainder = fqn

    dest = destination.replace("\\", "/").strip("/")
    parts = remainder.split("\\") if remainder else []
    if dest and parts:
        relative = os.path.join(dest.replace("/", os.sep), *parts)
    elif dest:
        relative = dest.replace("/", os.sep)
    elif parts:
        relative = os.path.join(*parts)
    else:
        return []
    relative = os.path.normpath(relative)
    if relative.endswith(".php"):
        return [relative]
    return [relative + ".php"]


def resolve_php_imports(
    raw_import_src: str,
    current_file: str,
    all_files: set[str],
    repo_root: str,
    ecosystem_context: Optional[EcosystemContext] = None,
) -> list[str]:
    """Resolve PHP `use` namespaces through Composer PSR-4 mappings only."""
    mappings = (ecosystem_context.psr4_mappings if ecosystem_context else {}) or {}
    if not mappings:
        return []

    ranked = sorted(mappings.items(), key=lambda item: len(item[0]), reverse=True)
    resolved: list[str] = []
    for spec in _parse_php_specifiers(raw_import_src):
        for namespace, destination in ranked:
            if not isinstance(namespace, str) or not isinstance(destination, str):
                continue
            candidates = _php_candidates_for_fqn(spec, namespace, destination)
            if not candidates:
                continue
            hit = _first_match(candidates, all_files, repo_root)
            if hit:
                resolved.append(hit)
            break
    return resolved


# ──────────────────────────────────────────────────────────────────────────────
# Main dispatcher
# ──────────────────────────────────────────────────────────────────────────────

_RESOLVERS = {
    "python":     resolve_python_imports,
    "javascript": resolve_js_imports,
    "typescript": resolve_js_imports,
    "tsx":        resolve_js_imports,
    "go":         resolve_go_imports,
    "c":          resolve_c_imports,
    "cpp":        resolve_c_imports,
    "java":       resolve_java_imports,
    "kotlin":     resolve_java_imports,
    "rust":       resolve_rust_imports,
    "php":        resolve_php_imports,
}


def resolve_imports(
    language: str,
    raw_import_text: str,
    current_file: str,
    all_files: set[str],
    repo_root: str,
    ecosystem_context: Optional[EcosystemContext] = None,
    *,
    raise_on_error: bool = False,
) -> list[str]:
    """
    Main entry point.

    Dispatches to the language-specific resolver and returns a deduplicated
    list of repo-relative file paths that `current_file` imports.

    Guarantees:
      - No path resolves to current_file itself (no self-loops)
      - All returned paths exist in all_files
      - Output is deterministic for the same inputs

    The default behavior preserves compatibility for existing callers: internal
    resolver failures are surfaced as a warning instead of silently returning an
    empty list. Callers with stricter requirements can opt into raising.
    """
    resolver = _RESOLVERS.get(language.lower())
    if resolver is None:
        return []

    try:
        raw = _invoke_resolver(
            resolver, raw_import_text, current_file, all_files, repo_root, ecosystem_context,
        )
    except Exception as exc:
        if raise_on_error:
            raise
        warnings.warn(
            f"Internal resolver error for {language!r}: {exc}",
            RuntimeWarning,
            stacklevel=2,
        )
        return []

    # Deduplicate, remove self-references, normalise
    seen: set[str] = set()
    result: list[str] = []
    for p in raw:
        p = os.path.normpath(p)
        if p != current_file and p not in seen and p in all_files:
            seen.add(p)
            result.append(p)

    return result
