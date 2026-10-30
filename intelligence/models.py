import os
from dataclasses import dataclass, field
from typing import Optional

# Map file extensions to Tree-sitter language names
EXTENSION_TO_LANGUAGE = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".cs": "c_sharp",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "c_sharp",
    ".scala": "scala",
    ".kt": "kotlin",
    ".swift": "swift",
    ".kt": "kotlin",
    ".lua": "lua",
    ".r": "r",
    ".toml": "toml",
    ".html": "html",
    ".css": "css",
    ".bash": "bash",
    ".sh": "bash",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
}


@dataclass(frozen=True)
class SymbolLocation:
    name: str
    kind: str
    start_line: int
    end_line: int


# Standard Tree-sitter tags convention:
# definition nodes are captured by @definition.<kind>, and their identifier by @name.
# This is preferred for deployment diff correlation across supported grammars.
TAGS_QUERIES = {
    "python": """
        (function_definition name: (identifier) @name) @definition.function
        (class_definition name: (identifier) @name) @definition.class
    """,
    "javascript": """
        (function_declaration name: (identifier) @name) @definition.function
        (method_definition name: (property_identifier) @name) @definition.method
        (class_declaration name: (identifier) @name) @definition.class
    """,
    "typescript": """
        (function_declaration name: (identifier) @name) @definition.function
        (method_definition name: (property_identifier) @name) @definition.method
        (class_declaration name: (type_identifier) @name) @definition.class
        (interface_declaration name: (type_identifier) @name) @definition.interface
    """,
    "tsx": """
        (function_declaration name: (identifier) @name) @definition.function
        (method_definition name: (property_identifier) @name) @definition.method
        (class_declaration name: (type_identifier) @name) @definition.class
        (interface_declaration name: (type_identifier) @name) @definition.interface
    """,
    "go": """
        (function_declaration name: (identifier) @name) @definition.function
        (method_declaration name: (field_identifier) @name) @definition.method
        (type_declaration (type_spec name: (type_identifier) @name)) @definition.struct
    """,
    "rust": """
        (function_item name: (identifier) @name) @definition.function
        (struct_item name: (type_identifier) @name) @definition.struct
        (enum_item name: (type_identifier) @name) @definition.enum
        (trait_item name: (type_identifier) @name) @definition.trait
    """,
    "java": """
        (class_declaration name: (identifier) @name) @definition.class
        (interface_declaration name: (identifier) @name) @definition.interface
        (method_declaration name: (identifier) @name) @definition.method
    """,
    "c": """
        (function_definition declarator: (function_declarator declarator: (identifier) @name)) @definition.function
    """,
    "cpp": """
        (function_definition declarator: (function_declarator declarator: (identifier) @name)) @definition.function
        (class_specifier name: (type_identifier) @name) @definition.class
    """,
    "ruby": """
        (method name: (identifier) @name) @definition.method
        (class name: (constant) @name) @definition.class
        (module name: (constant) @name) @definition.module
    """,
    "php": """
        (function_definition name: (name) @name) @definition.function
        (class_declaration name: (name) @name) @definition.class
    """,
}


# Query patterns per language to extract legacy symbols and imports.
# Use TAGS_QUERIES for definition ranges in new integrations.
SYMBOL_QUERIES = {
    "python": {
        "functions": "(function_definition name: (identifier) @func)",
        "classes": "(class_definition name: (identifier) @cls)",
        "imports": "(import_statement) @import",
        "from_imports": "(import_from_statement) @import",
    },
    "javascript": {
        "functions": """
            (function_declaration name: (identifier) @func)
            (arrow_function) @func
            (method_definition name: (property_identifier) @func)
        """,
        "classes": "(class_declaration name: (identifier) @cls)",
        "imports": "(import_statement) @import",
    },
    "typescript": {
        "functions": """
            (function_declaration name: (identifier) @func)
            (arrow_function) @func
            (method_definition name: (property_identifier) @func)
        """,
        "classes": "(class_declaration name: (identifier) @cls)",
        "imports": "(import_statement) @import",
        "interfaces": "(interface_declaration name: (type_identifier) @iface)",
    },
    "go": {
        "functions": "(function_declaration name: (identifier) @func)",
        "methods": "(method_declaration name: (field_identifier) @func)",
        "structs": "(type_declaration (type_spec name: (type_identifier) @struct))",
        "imports": "(import_declaration) @import",
    },
    "rust": {
        "functions": "(function_item name: (identifier) @func)",
        "structs": "(struct_item name: (type_identifier) @struct)",
        "enums": "(enum_item name: (type_identifier) @enum)",
        "traits": "(trait_item name: (type_identifier) @trait)",
        "imports": "(use_declaration) @import",
    },
    "java": {
        "classes": "(class_declaration name: (identifier) @cls)",
        "methods": "(method_declaration name: (identifier) @func)",
        "interfaces": "(interface_declaration name: (identifier) @iface)",
        "imports": "(import_declaration) @import",
    },
    "c": {
        "functions": "(function_definition declarator: (function_declarator declarator: (identifier) @func))",
        "includes": "(preproc_include) @import",
    },
    "cpp": {
        "functions": "(function_definition declarator: (function_declarator declarator: (identifier) @func))",
        "classes": "(class_specifier name: (type_identifier) @cls)",
        "includes": "(preproc_include) @import",
    },
    "ruby": {
        "functions": "(method name: (identifier) @func)",
        "classes": "(class name: (constant) @cls)",
        "modules": "(module name: (constant) @module)",
    },
    "php": {
        "functions": "(function_definition name: (name) @func)",
        "classes": "(class_declaration name: (name) @cls)",
        "imports": "(namespace_use_declaration) @import",
    },
}

@dataclass
class EcosystemContext:
    """Workspace-level module routing captured from manifests before file walk."""
    psr4_mappings: dict[str, str] = field(default_factory=dict)       # PHP Composer PSR-4 Map
    subpath_imports: dict[str, str] = field(default_factory=dict)     # package.json "#imports"
    python_path_aliases: dict[str, str] = field(default_factory=dict)  # poetry/pyproject paths
    detected_frameworks: list[str] = field(default_factory=list)      # ["laravel", "nextjs", "spring-boot"]

    def to_dict(self) -> dict:
        return {
            "psr4_mappings": dict(self.psr4_mappings),
            "subpath_imports": dict(self.subpath_imports),
            "python_path_aliases": dict(self.python_path_aliases),
            "detected_frameworks": list(self.detected_frameworks),
        }


@dataclass
class FileAnalysis:
    path: str
    language: str
    lines: int
    size_bytes: int
    functions: list[str] = field(default_factory=list)
    classes: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    interfaces: list[str] = field(default_factory=list)
    structs: list[str] = field(default_factory=list)
    symbol_locations: list[SymbolLocation] = field(default_factory=list)
    parse_errors: list[dict] = field(default_factory=list)
    lexical_terms: dict[str, int] = field(default_factory=dict)
    analysis_tier: str = "unknown"
    todos: list[str] = field(default_factory=list)
    error: Optional[str] = None

@dataclass
class RepoIntelligence:
    repo_path: str
    repo_url: str
    total_files: int = 0
    total_lines: int = 0
    total_size_bytes: int = 0
    language_stats: dict = field(default_factory=dict)
    file_analyses: list[FileAnalysis] = field(default_factory=list)
    top_functions: list[tuple] = field(default_factory=list)
    all_classes: list[str] = field(default_factory=list)
    all_interfaces: list[str] = field(default_factory=list)
    all_structs: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    todos: list[dict] = field(default_factory=list)
    git_info: dict = field(default_factory=dict)
    ecosystem_context: Optional[EcosystemContext] = None
