import os
import re
import warnings
from collections import Counter
from typing import Optional

# Suppress tree-sitter 0.21 / tree-sitter-languages compatibility FutureWarning
warnings.filterwarnings("ignore", category=FutureWarning, module="tree_sitter")


from .models import (
    FileAnalysis,
    SymbolLocation,
    EXTENSION_TO_LANGUAGE,
    SYMBOL_QUERIES,
    TAGS_QUERIES,
)
from .query_engine import tokenize_identifiers

#Skip directories that are commonly not relevant for source code analysis
SKIP_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv", ".env",
    "dist", "build", ".next", ".nuxt", "target", "vendor",
    ".idea", ".vscode", ".mypy_cache", ".pytest_cache",
}

#Skip files with these extensions (case-insensitive)
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".mp4", ".mp3", ".wav", ".avi", ".mov",
    ".zip", ".tar", ".gz", ".bz2", ".rar", ".7z",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".ttf", ".woff", ".woff2", ".eot",
    ".lock", ".min.js", ".min.css",
    ".pyc", ".pyo", ".class",
    ".bin", ".exe", ".so", ".dll", ".dylib",
    ".db", ".sqlite", ".sqlite3",
}

TODO_PATTERN = re.compile(r"(TODO|FIXME|HACK|XXX|BUG|NOTE):\s*(.*)", re.IGNORECASE)


def get_parser(language_name: str):
    """Lazily loads a Tree-sitter parser for the given language."""
    try:
        from tree_sitter_languages import get_parser as _get_parser
        return _get_parser(language_name)
    except Exception:
        return None


def get_language(language_name: str):
    """Lazily loads a Tree-sitter Language object."""
    try:
        from tree_sitter_languages import get_language as _get_language
        return _get_language(language_name)
    except Exception:
        return None


def extract_node_text(node, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def run_query(parser, language_name: str, source_bytes: bytes, query_str: str) -> list[str]:
    """Runs a Tree-sitter query on the source and returns matched node texts."""
    return [
        location.name
        for location in run_symbol_query(parser, language_name, source_bytes, query_str)
    ]


def run_symbol_query(parser, language_name: str, source_bytes: bytes, query_str: str) -> list[SymbolLocation]:
    """Runs a legacy Tree-sitter query and retains each matched source range."""
    try:
        lang = get_language(language_name)
        if lang is None:
            return []
        tree = parser.parse(source_bytes)
        captures = lang.query(query_str).captures(tree.root_node)
        locations: list[SymbolLocation] = []
        seen: set[tuple[str, str, int, int]] = set()

        for item in captures:
            if isinstance(item, tuple):
                node, capture_name = item
                kind = capture_name.lstrip("@").replace("_", "-")
            else:
                node = item
                kind = "symbol"

            target_node = node
            if kind in {"func", "cls", "interface", "struct", "enum", "trait", "module"}:
                target_node = node.parent or node
            location = SymbolLocation(
                name=extract_node_text(node, source_bytes),
                kind=kind,
                start_line=target_node.start_point[0] + 1,
                end_line=max(target_node.start_point[0] + 1, target_node.end_point[0] + 1),
            )
            identity = (location.name, location.kind, location.start_line, location.end_line)
            if identity not in seen:
                seen.add(identity)
                locations.append(location)
        return locations
    except Exception:
        return []


def run_tags_query(parser, language_name: str, source_bytes: bytes) -> list[SymbolLocation]:
    """Extract definitions using Tree-sitter's standardized @definition tags.

    Returns an empty list for an unknown language or invalid tag query. Callers
    may then use their explicit legacy query as a compatibility fallback.
    """
    query_str = TAGS_QUERIES.get(language_name)
    if not query_str:
        return []

    try:
        lang = get_language(language_name)
        if lang is None:
            return []
        captures = lang.query(query_str).captures(parser.parse(source_bytes).root_node)
        names: list[tuple[int, int, str]] = []
        definitions: list[tuple[str, object]] = []

        for item in captures:
            if not isinstance(item, tuple):
                continue
            node, capture_name = item
            if capture_name == "name":
                names.append((node.start_byte, node.end_byte, extract_node_text(node, source_bytes)))
            elif capture_name.startswith("definition."):
                kind = capture_name.split(".", 1)[1]
                definitions.append((kind, node))

        locations: list[SymbolLocation] = []
        for kind, definition_node in definitions:
            name_matches = [
                name
                for start_byte, end_byte, name in names
                if definition_node.start_byte <= start_byte and end_byte <= definition_node.end_byte
            ]
            name = name_matches[0] if name_matches else ""
            if not name:
                continue
            locations.append(SymbolLocation(
                name=name,
                kind=kind,
                start_line=definition_node.start_point[0] + 1,
                end_line=max(definition_node.start_point[0] + 1, definition_node.end_point[0] + 1),
            ))
        return locations
    except Exception:
        return []


def run_structural_ast_fallback(parser, language_name: str, source_bytes: bytes) -> tuple[list[SymbolLocation], list[dict]]:
    """Capture language-neutral structural nodes and parse errors."""
    try:
        tree = parser.parse(source_bytes)
        locations: list[SymbolLocation] = []
        parse_errors: list[dict] = []
        seen: set[tuple[str, int, int]] = set()

        def visit(node) -> None:
            node_type = node.type.lower()
            kind: Optional[str] = None
            if node_type in {"error"} or "error" in node_type:
                kind = "ERROR"
            elif "declaration" in node_type or "definition" in node_type:
                kind = "declaration"
            elif "assignment" in node_type or "initializer" in node_type:
                kind = "assignment"
            elif node_type.endswith("block") or node_type in {"block", "statement_block", "compound_statement"}:
                kind = "block"

            if kind:
                identity = (kind, node.start_point[0] + 1, node.end_point[0] + 1)
                if kind == "ERROR":
                    parse_errors.append({
                        "kind": kind,
                        "start_line": node.start_point[0] + 1,
                        "end_line": max(node.start_point[0] + 1, node.end_point[0] + 1),
                        "text": extract_node_text(node, source_bytes)[:500],
                    })
                elif identity not in seen:
                    seen.add(identity)
                    name = ""
                    try:
                        name_node = node.child_by_field_name("name")
                        if name_node:
                            name = extract_node_text(name_node, source_bytes)
                    except Exception:
                        pass
                    if not name:
                        match = re.search(r"[A-Za-z_]\w*", extract_node_text(node, source_bytes))
                        name = match.group(0) if match else node_type
                    locations.append(SymbolLocation(
                        name=name,
                        kind=kind,
                        start_line=node.start_point[0] + 1,
                        end_line=max(node.start_point[0] + 1, node.end_point[0] + 1),
                    ))

            for child in node.children:
                visit(child)

        visit(tree.root_node)
        return locations, parse_errors
    except Exception:
        return [], []


def get_symbol_locations(parser, language_name: str, source_bytes: bytes) -> list[SymbolLocation]:
    """Return tagged definitions, falling back to explicit legacy queries."""
    tagged = run_tags_query(parser, language_name, source_bytes)
    if tagged:
        return tagged

    locations: list[SymbolLocation] = []
    for query_name, query_str in SYMBOL_QUERIES.get(language_name, {}).items():
        if query_name in {"imports", "from_imports", "includes"}:
            continue
        locations.extend(run_symbol_query(parser, language_name, source_bytes, query_str))
    return locations


def extract_todos(source: str, file_path: str) -> list[dict]:
    """Finds TODO/FIXME style comments in source code."""
    todos = []
    for i, line in enumerate(source.splitlines(), start=1):
        match = TODO_PATTERN.search(line)
        if match:
            todos.append({
                "type": match.group(1).upper(),
                "message": match.group(2).strip(),
                "file": file_path,
                "line": i,
            })
    return todos


def should_skip(path: str) -> bool:
    """Returns True if a file or directory should be skipped."""
    name = os.path.basename(path)
    if name in SKIP_DIRS:
        return True
    ext = os.path.splitext(name)[1].lower()
    if ext in SKIP_EXTENSIONS:
        return True
    # Skip minified files
    if ".min." in name:
        return True
    return False


def analyze_file(file_path: str, repo_root: str) -> Optional[FileAnalysis]:
    """Analyzes a single file using Tree-sitter and heuristics."""
    rel_path = os.path.relpath(file_path, repo_root)

    if should_skip(file_path):
        return None

    ext = os.path.splitext(file_path)[1].lower()
    language_name = EXTENSION_TO_LANGUAGE.get(ext)

    try:
        size_bytes = os.path.getsize(file_path)
        # Skip very large files (>1MB)
        if size_bytes > 1_000_000:
            return None

        with open(file_path, "rb") as f:
            source_bytes = f.read()

        source_str = source_bytes.decode("utf-8", errors="replace")
        lines = len(source_str.splitlines())
        todos = extract_todos(source_str, rel_path)

        analysis = FileAnalysis(
            path=rel_path,
            language=language_name or "unknown",
            lines=lines,
            size_bytes=size_bytes,
            todos=todos,
            lexical_terms=dict(Counter(tokenize_identifiers(source_str))),
            analysis_tier="lexical",
        )

        if language_name:
            parser = get_parser(language_name)
            if parser:
                queries = SYMBOL_QUERIES.get(language_name, {})

                if "functions" in queries:
                    analysis.functions = run_query(parser, language_name, source_bytes, queries["functions"])
                if "classes" in queries:
                    analysis.classes = run_query(parser, language_name, source_bytes, queries["classes"])
                if "imports" in queries:
                    analysis.imports += run_query(parser, language_name, source_bytes, queries["imports"])
                if "from_imports" in queries:
                    analysis.imports += run_query(parser, language_name, source_bytes, queries["from_imports"])
                if "interfaces" in queries:
                    analysis.interfaces = run_query(parser, language_name, source_bytes, queries["interfaces"])
                if "structs" in queries:
                    analysis.structs = run_query(parser, language_name, source_bytes, queries["structs"])

                locations = get_symbol_locations(parser, language_name, source_bytes)
                if locations:
                    analysis.analysis_tier = "tags"
                    analysis.symbol_locations = locations
                else:
                    structural, parse_errors = run_structural_ast_fallback(parser, language_name, source_bytes)
                    analysis.analysis_tier = "structural"
                    analysis.symbol_locations = structural
                    analysis.parse_errors = parse_errors

        return analysis

    except (IOError, OSError) as e:
        return FileAnalysis(
            path=rel_path,
            language=language_name or "unknown",
            lines=0,
            size_bytes=0,
            error=str(e),
        )


def walk_repository(repo_root: str) -> list[str]:
    """Walks the repository, returning all non-skipped file paths."""
    all_files = []
    for dirpath, dirnames, filenames in os.walk(repo_root):
        # Prune skipped directories in-place to avoid descending into them
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

        for filename in filenames:
            full_path = os.path.join(dirpath, filename)
            if not should_skip(full_path):
                all_files.append(full_path)

    return all_files
