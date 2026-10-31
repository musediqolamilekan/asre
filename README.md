# ASRE — Autonomous Software Reliability Engineer

ASRE is a deterministic repository intelligence and incident-to-repair pipeline. It analyzes source repositories using Tree-sitter AST extraction, cross-language import resolution, dependency/impact graphs, and git commit churn to build explainable file risk profiles and structured repair contexts for software incidents.

---

## Architecture & Project Structure

```text
asre/
├── main.py                        # CLI entrypoint and workflow orchestrator
├── requirements.txt               # Python dependencies
├── intelligence/                  # Read-only repository & graph intelligence
│   ├── cloner.py                  # Git repository cloning and local cache management
│   ├── scanner.py                 # Repository and ecosystem manifest scanner
│   ├── analyzer.py                # Tree-sitter AST symbol, import, and lexical extractor
│   ├── models.py                  # Core data structures and Tree-sitter query definitions
│   ├── resolver.py                # Cross-language import-to-filepath resolver
│   ├── dependency_graph.py        # Directed file dependency & transitive impact graph
│   ├── git_analyzer.py            # 90-day git commit churn & deployment diff analyzer
│   ├── risk_scorer.py             # Deterministic weighted file risk calculator
│   ├── file_profile.py            # Per-file intelligence profile builder
│   └── query_engine.py            # Multi-signal keyword & BM25 codebase query engine
├── repair/                        # Incident mapping, patch validation & execution
│   ├── incident_mapper.py         # Multi-language traceback parser & RepairContext builder
│   ├── patch_planner.py           # PatchPlan contract & deterministic diff/command validator
│   ├── patch_executor.py          # Isolated git worktree patch applier & test verifier
│   └── repair_runs.py             # Persistent .asre/runs/ artifact store
├── reporting/                     # Terminal UI renderers
│   ├── reporter.py                # Repository intelligence summary renderer
│   ├── graph_reporter.py          # Dependency graph & impact report renderer
│   └── profile_reporter.py        # File profile, reverse-dependency & query renderer
├── examples/                      # Sample incident and patch-plan payloads
│   └── click-001/
└── tests/                         # Automated unit & CLI integration test suite
```

---

## Capabilities

1. **Multi-Language Static Analysis (`intelligence/`)**
   - Extracts functions, classes, interfaces, structs, symbol line ranges, imports, and TODOs via Tree-sitter with zero-knowledge lexical BM25 fallback.
   - Discovers ecosystem manifests across Python (`pyproject.toml`, `requirements.txt`), JavaScript/TypeScript (`package.json`, `tsconfig.json`), Go (`go.mod`), Rust (`Cargo.toml`), and PHP (`composer.json` PSR-4).
2. **Code Relationship Graph & Risk Scoring (`intelligence/`)**
   - Resolves relative, aliased, and package-internal imports into canonical repository-relative file paths.
   - Computes deterministic, explainable risk scores (`0–90`) combining direct dependents, transitive dependents, 90-day git churn, and public symbol surface area.
3. **Incident Triage & Deterministic Repair Pipeline (`repair/`)**
   - Parses stack frames across Python, JavaScript/TypeScript (V8/Node), Java/Kotlin/Scala (JVM), Go, Rust, Ruby, PHP, and compiled/scripting languages while preserving frame ordering and function names.
   - Maps stack frames to repository files with physical symlink containment, normalized collision detection, JVM package qualification, and external dependency filtering.
   - Builds graph-ranked `RepairContext` objects, validates `PatchPlan` diffs and allowlisted test commands deterministically, and executes candidate patches inside temporary Git worktrees.

---

## Setup

Requires **Python 3.11+** and **Git**.

```bash
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
```

---

## CLI Usage

### 1. Repository Scan & Summary
```bash
# Scan a remote GitHub repository (clones into .repo_cache/)
./venv/bin/python main.py pallets/click

# Scan a local repository directory
./venv/bin/python main.py --local /path/to/repo
```

### 2. Dependency Graph, Impact & Risk Analysis
```bash
# Display the code relationship graph overview
./venv/bin/python main.py --local /path/to/repo --graph

# List files ranked by deterministic risk/impact score
./venv/bin/python main.py --local /path/to/repo --list-critical

# Inspect what breaks if a specific file breaks
./venv/bin/python main.py --local /path/to/repo --impact src/click/core.py

# Inspect reverse dependency tree ("who imports this file?")
./venv/bin/python main.py --local /path/to/repo --who-uses src/click/core.py

# Display the full intelligence profile for a file
./venv/bin/python main.py --local /path/to/repo --profile src/click/core.py
```

### 3. Codebase Query Engine
```bash
./venv/bin/python main.py --local /path/to/repo --query "OptionParser usage error"
```

### 4. Incident Context & Patch Verification
```bash
# Build and inspect deterministic RepairContext for an incident
./venv/bin/python main.py --local /path/to/repo \
  --incident examples/click-001/incident.json \
  --explain-context

# Validate a proposed patch plan against the incident RepairContext
./venv/bin/python main.py --local /path/to/repo \
  --incident examples/click-001/incident.json \
  --patch-plan examples/click-001/patch-plan.json

# Apply a validated patch plan in an isolated Git worktree, run tests, and save artifacts
./venv/bin/python main.py --local /path/to/repo \
  --incident examples/click-001/incident.json \
  --patch-plan examples/click-001/patch-plan.json \
  --verify-patch-plan \
  --repair-run-dir .asre/runs
```

---

## Running Tests

Run the full unit and CLI integration test suite using `unittest`:

```bash
./venv/bin/python -m unittest discover -s tests -v
```

Run a specific test module:

```bash
./venv/bin/python -m unittest tests/test_incident_mapper.py -v
```
