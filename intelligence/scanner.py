import os
import json
import warnings
from datetime import datetime
from git import Repo, InvalidGitRepositoryError

from .models import EcosystemContext, RepoIntelligence
from .analyzer import walk_repository, analyze_file

try:
    import tomllib
except ImportError:  # pragma: no cover - Python < 3.11
    tomllib = None

# Files that indicate dependencies / package managers
DEPENDENCY_FILES = {
    "requirements.txt": "Python (pip)",
    "Pipfile": "Python (pipenv)",
    "pyproject.toml": "Python (pyproject)",
    "package.json": "JavaScript/Node (npm)",
    "yarn.lock": "JavaScript/Node (yarn)",
    "pnpm-lock.yaml": "JavaScript/Node (pnpm)",
    "go.mod": "Go (modules)",
    "Cargo.toml": "Rust (cargo)",
    "pom.xml": "Java (maven)",
    "build.gradle": "Java/Kotlin (gradle)",
    "Gemfile": "Ruby (bundler)",
    "composer.json": "PHP (composer)",
    "pubspec.yaml": "Dart/Flutter",
    "mix.exs": "Elixir (mix)",
}


def get_git_info(repo_path: str) -> dict:
    """Extracts git metadata from a local repository."""
    try:
        repo = Repo(repo_path)
        head_commit = repo.head.commit
        
        contributors = {}
        for commit in repo.iter_commits(max_count=500):
            author = commit.author.email or commit.author.name
            contributors[author] = contributors.get(author, 0) + 1

        top_contributors = sorted(contributors.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            "default_branch": repo.active_branch.name,
            "total_commits": sum(1 for _ in repo.iter_commits(max_count=5000)),
            "last_commit_sha": head_commit.hexsha[:8],
            "last_commit_message": head_commit.message.strip(),
            "last_commit_date": datetime.fromtimestamp(head_commit.committed_date).isoformat(),
            "last_commit_author": head_commit.author.name,
            "top_contributors": top_contributors,
            "total_branches": len(list(repo.branches)),
            "total_tags": len(list(repo.tags)),
        }
    except (InvalidGitRepositoryError, Exception) as e:
        return {"error": str(e)}


def _append_unique(items: list[str], value: str) -> None:
    if value and value not in items:
        items.append(value)


def _first_string_target(value) -> str | None:
    """Pick a deterministic filesystem target from a Node imports map value."""
    if isinstance(value, str) and value:
        return value
    if isinstance(value, list):
        for item in value:
            found = _first_string_target(item)
            if found:
                return found
        return None
    if isinstance(value, dict):
        if "default" in value:
            found = _first_string_target(value["default"])
            if found:
                return found
        for item in value.values():
            found = _first_string_target(item)
            if found:
                return found
    return None


def _read_text_manifest(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError as exc:
        warnings.warn(f"Failed to read {path}: {exc}", RuntimeWarning, stacklevel=2)
        return None


def _read_json_manifest(path: str) -> dict | None:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception as exc:
        warnings.warn(f"Failed to parse {path}: {exc}", RuntimeWarning, stacklevel=2)
        return None
    return payload if isinstance(payload, dict) else None


def _normalize_psr4_prefix(prefix: str) -> str:
    return prefix.replace("/", "\\")


def parse_composer_manifest(repo_path: str, context: EcosystemContext) -> None:
    path = os.path.join(repo_path, "composer.json")
    if not os.path.isfile(path):
        return
    data = _read_json_manifest(path)
    if data is None:
        return

    autoload = data.get("autoload") if isinstance(data.get("autoload"), dict) else {}
    psr4 = autoload.get("psr-4") if isinstance(autoload.get("psr-4"), dict) else {}
    for namespace, destination in psr4.items():
        if not isinstance(namespace, str):
            continue
        target = destination if isinstance(destination, str) else _first_string_target(destination)
        if not isinstance(target, str) or not target:
            continue
        context.psr4_mappings[_normalize_psr4_prefix(namespace)] = target.replace("\\", "/").rstrip("/") + "/"

    require = data.get("require") if isinstance(data.get("require"), dict) else {}
    require_dev = data.get("require-dev") if isinstance(data.get("require-dev"), dict) else {}
    packages = set(require) | set(require_dev)
    if "laravel/framework" in packages:
        _append_unique(context.detected_frameworks, "laravel")


def parse_package_json_manifest(repo_path: str, context: EcosystemContext) -> None:
    path = os.path.join(repo_path, "package.json")
    if not os.path.isfile(path):
        return
    data = _read_json_manifest(path)
    if data is None:
        return

    imports = data.get("imports") if isinstance(data.get("imports"), dict) else {}
    for alias, destination in imports.items():
        if not isinstance(alias, str) or not alias:
            continue
        target = _first_string_target(destination)
        if not target:
            continue
        context.subpath_imports[alias] = target

    dependency_names: set[str] = set()
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        block = data.get(key)
        if isinstance(block, dict):
            dependency_names.update(str(name) for name in block)

    if "next" in dependency_names or "nextjs" in dependency_names:
        _append_unique(context.detected_frameworks, "nextjs")
    if "express" in dependency_names:
        _append_unique(context.detected_frameworks, "express")
    if any(name == "nest" or name == "nestjs" or name.startswith("@nestjs/") for name in dependency_names):
        _append_unique(context.detected_frameworks, "nest")


def parse_java_signatures(repo_path: str, context: EcosystemContext) -> None:
    try:
        if any(
            os.path.isfile(os.path.join(repo_path, filename))
            for filename in ("pom.xml", "build.gradle")
        ):
            _append_unique(context.detected_frameworks, "spring-boot")
    except Exception as exc:
        warnings.warn(
            f"Failed to inspect Java manifests in {repo_path}: {exc}",
            RuntimeWarning,
            stacklevel=2,
        )


def _tag_python_frameworks(blob: str, context: EcosystemContext) -> None:
    lowered = blob.lower()
    if "django" in lowered:
        _append_unique(context.detected_frameworks, "django")
    if "fastapi" in lowered:
        _append_unique(context.detected_frameworks, "fastapi")


def parse_python_signatures(repo_path: str, context: EcosystemContext) -> None:
    pyproject_path = os.path.join(repo_path, "pyproject.toml")
    if os.path.isfile(pyproject_path):
        try:
            if tomllib is None:
                raise RuntimeError("tomllib is unavailable")
            with open(pyproject_path, "rb") as handle:
                data = tomllib.load(handle)
        except Exception as exc:
            warnings.warn(f"Failed to parse {pyproject_path}: {exc}", RuntimeWarning, stacklevel=2)
            data = None
        if isinstance(data, dict):
            package_dir = (
                data.get("tool", {}).get("setuptools", {}).get("package-dir")
                if isinstance(data.get("tool"), dict)
                else None
            )
            if isinstance(package_dir, dict):
                for key, value in package_dir.items():
                    if isinstance(key, str) and isinstance(value, str) and value:
                        context.python_path_aliases[key] = value

            poetry = data.get("tool", {}).get("poetry") if isinstance(data.get("tool"), dict) else None
            if isinstance(poetry, dict):
                packages = poetry.get("packages")
                if isinstance(packages, list):
                    for entry in packages:
                        if not isinstance(entry, dict):
                            continue
                        include = entry.get("include")
                        from_dir = entry.get("from", "")
                        if isinstance(include, str) and include:
                            dest = os.path.join(from_dir, include) if isinstance(from_dir, str) and from_dir else include
                            context.python_path_aliases[include.replace("/", ".")] = dest

                dependencies = poetry.get("dependencies")
                if isinstance(dependencies, dict):
                    _tag_python_frameworks(" ".join(str(name) for name in dependencies), context)

            project = data.get("project") if isinstance(data.get("project"), dict) else {}
            deps = project.get("dependencies")
            if isinstance(deps, list):
                _tag_python_frameworks(" ".join(str(item) for item in deps), context)

    requirements_path = os.path.join(repo_path, "requirements.txt")
    if os.path.isfile(requirements_path):
        text = _read_text_manifest(requirements_path)
        if text is not None:
            _tag_python_frameworks(text, context)


def parse_go_signatures(repo_path: str, context: EcosystemContext) -> None:
    path = os.path.join(repo_path, "go.mod")
    if os.path.isfile(path):
        _append_unique(context.detected_frameworks, "go")


def discover_ecosystem_context(repo_path: str) -> EcosystemContext:
    """Parse root manifests into a deterministic EcosystemContext."""
    context = EcosystemContext()
    parse_composer_manifest(repo_path, context)
    parse_package_json_manifest(repo_path, context)
    parse_java_signatures(repo_path, context)
    parse_python_signatures(repo_path, context)
    parse_go_signatures(repo_path, context)
    return context


def detect_dependencies(repo_path: str) -> list[str]:
    """Detects which package managers / dependency files are present."""
    found = []
    for filename, label in DEPENDENCY_FILES.items():
        if os.path.exists(os.path.join(repo_path, filename)):
            found.append(label)
    return found


def scan_repository(repo_path: str, repo_url: str = "", verbose: bool = True) -> RepoIntelligence:
    """
    Performs a comprehensive scan of a local repository.
    Returns a RepoIntelligence dataclass with all extracted data.
    """
    intel = RepoIntelligence(repo_path=repo_path, repo_url=repo_url)

    if verbose:
        print("  → Discovering ecosystem manifests...")
    intel.ecosystem_context = discover_ecosystem_context(repo_path)
    if verbose and intel.ecosystem_context.detected_frameworks:
        print("      Frameworks: " + ", ".join(intel.ecosystem_context.detected_frameworks))

    if verbose:
        print("  → Gathering git metadata...")
    intel.git_info = get_git_info(repo_path)

    if verbose:
        print("  → Detecting dependencies...")
    intel.dependencies = detect_dependencies(repo_path)

    if verbose:
        print("  → Walking repository files...")
    all_files = walk_repository(repo_path)
    intel.total_files = len(all_files)

    if verbose:
        print(f"  → Analyzing {intel.total_files} files with Tree-sitter...")

    lang_bytes: dict[str, int] = {}

    for i, file_path in enumerate(all_files, start=1):
        if verbose and i % 50 == 0:
            print(f"      [{i}/{intel.total_files}] files analyzed...")

        file_analysis = analyze_file(file_path, repo_path)
        if file_analysis is None:
            continue

        intel.file_analyses.append(file_analysis)
        intel.total_lines += file_analysis.lines
        intel.total_size_bytes += file_analysis.size_bytes

        # Aggregate language bytes
        lang = file_analysis.language
        if lang and lang != "unknown":
            lang_bytes[lang] = lang_bytes.get(lang, 0) + file_analysis.size_bytes

        # Aggregate symbols
        intel.all_classes.extend(file_analysis.classes)
        intel.all_interfaces.extend(file_analysis.interfaces)
        intel.all_structs.extend(file_analysis.structs)
        intel.todos.extend(file_analysis.todos)

    # Compute language percentages
    total_bytes = sum(lang_bytes.values())
    if total_bytes > 0:
        intel.language_stats = {
            lang: {
                "bytes": b,
                "percentage": round((b / total_bytes) * 100, 2),
            }
            for lang, b in sorted(lang_bytes.items(), key=lambda x: x[1], reverse=True)
        }

    # Build top functions (file + count)
    func_counts = {}
    for fa in intel.file_analyses:
        for fn in fa.functions:
            func_counts[fn] = func_counts.get(fn, 0) + 1

    intel.top_functions = sorted(func_counts.items(), key=lambda x: x[1], reverse=True)[:25]

    return intel


def to_dict(intel: RepoIntelligence) -> dict:
    """Converts a RepoIntelligence object to a serializable dict."""
    return {
        "repo_url": intel.repo_url,
        "repo_path": intel.repo_path,
        "summary": {
            "total_files": intel.total_files,
            "total_lines": intel.total_lines,
            "total_size_bytes": intel.total_size_bytes,
            "total_size_mb": round(intel.total_size_bytes / (1024 * 1024), 2),
        },
        "git_info": intel.git_info,
        "language_stats": intel.language_stats,
        "dependencies": intel.dependencies,
        "ecosystem_context": (
            intel.ecosystem_context.to_dict()
            if intel.ecosystem_context is not None
            else EcosystemContext().to_dict()
        ),
        "symbols": {
            "total_functions": sum(len(f.functions) for f in intel.file_analyses),
            "total_classes": len(intel.all_classes),
            "total_interfaces": len(intel.all_interfaces),
            "total_structs": len(intel.all_structs),
            "top_functions": intel.top_functions,
            "classes": sorted(set(intel.all_classes)),
            "interfaces": sorted(set(intel.all_interfaces)),
            "structs": sorted(set(intel.all_structs)),
        },
        "todos": {
            "total": len(intel.todos),
            "items": intel.todos,
        },
        "files": [
            {
                "path": fa.path,
                "language": fa.language,
                "lines": fa.lines,
                "size_bytes": fa.size_bytes,
                "functions": fa.functions,
                "classes": fa.classes,
                "imports": [imp[:120] for imp in fa.imports],  # truncate long imports
                "todos": len(fa.todos),
                "analysis_tier": fa.analysis_tier,
                "parse_errors": fa.parse_errors,
                **({"error": fa.error} if fa.error else {}),
            }
            for fa in intel.file_analyses
        ],
    }
