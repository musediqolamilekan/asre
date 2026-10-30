"""
Terminal renderer for the Dependency Graph Engine.
Displays the CODE RELATIONSHIP GRAPH view and impact reports.
"""

import os
from intelligence.dependency_graph import DependencyGraph, ImpactReport

RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
CYAN    = "\033[96m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
MAGENTA = "\033[95m"
BLUE    = "\033[94m"
WHITE   = "\033[97m"


def _risk_color(risk: str) -> str:
    return {
        "High":   RED,
        "Medium": YELLOW,
        "Low":    GREEN,
    }.get(risk, DIM)


def _risk_icon(risk: str) -> str:
    return {"High": "🔴", "Medium": "🟡", "Low": "🟢"}.get(risk, "⚪")


def _hr(char="─", width=62):
    print(f"{DIM}{char * width}{RESET}")


def _header(title: str, icon: str = ""):
    print(f"\n{BOLD}{CYAN}{icon}  {title}{RESET}")
    _hr()


def _basename(path: str) -> str:
    return os.path.basename(path)


def _tree_list(items: list[str], label: str, color: str = DIM, max_show: int = 8):
    """Prints a tree-style list."""
    if not items:
        return
    print(f"\n  {BOLD}{label}:{RESET}")
    shown = items[:max_show]
    for i, item in enumerate(shown):
        connector = "└──" if i == len(shown) - 1 and len(items) <= max_show else "├──"
        print(f"   {DIM}{connector}{RESET} {color}{_basename(item)}{RESET}  {DIM}{item}{RESET}")
    if len(items) > max_show:
        print(f"   {DIM}└── ...and {len(items) - max_show} more{RESET}")


def print_graph_overview(graph: DependencyGraph, top_n: int = 15):
    """Prints the full CODE RELATIONSHIP GRAPH overview."""
    stats = graph.stats()
    critical = graph.most_critical(top_n=top_n)

    print(f"\n{BOLD}{'═' * 62}{RESET}")
    print(f"{BOLD}{CYAN}  🕸️  CODE RELATIONSHIP GRAPH{RESET}")
    print(f"{BOLD}{'═' * 62}{RESET}")

    # ── Graph stats ────────────────────────────────────────────────
    _header("GRAPH STATISTICS", "📊")
    print(f"  {'Nodes (files):':<28} {BOLD}{stats['total_nodes']:,}{RESET}")
    print(f"  {'Edges (import links):':<28} {BOLD}{stats['total_edges']:,}{RESET}")
    print(f"  {'Isolated files:':<28} {BOLD}{stats['isolated_nodes']:,}{RESET}")
    print(f"  {'Max impact score:':<28} {BOLD}{stats['max_impact_score']:,}{RESET}")
    print(f"  {'Avg impact score:':<28} {BOLD}{stats['avg_impact_score']}{RESET}")

    if not critical:
        print(f"\n  {DIM}No dependency edges found. Imports may use non-relative paths.{RESET}")
        return

    # ── Critical nodes ─────────────────────────────────────────────
    _header("MOST CRITICAL FILES (by transitive impact)", "⚡")
    print(f"  {'File':<40} {'Impact':>7}  {'Risk':<8}  Dependents")
    _hr("─", 62)

    for path, score, risk in critical:
        rc = _risk_color(risk)
        icon = _risk_icon(risk)
        name = _basename(path)[:38]
        direct = len(graph.dependents(path))
        print(
            f"  {WHITE}{name:<40}{RESET}"
            f"  {rc}{score:>5}{RESET}"
            f"  {rc}{icon} {risk:<6}{RESET}"
            f"  {DIM}{direct} direct{RESET}"
        )

    # ── Relationship map for top 5 ─────────────────────────────────
    _header("RELATIONSHIP MAP (top 5 critical files)", "🗺️")
    for path, score, risk in critical[:5]:
        rc = _risk_color(risk)
        icon = _risk_icon(risk)
        name = _basename(path)
        deps = graph.dependencies(path)
        rdeps = graph.dependents(path)

        print(f"\n  {BOLD}{WHITE}{name}{RESET}  {rc}{icon} {risk} risk  (score: {score}){RESET}")
        print(f"  {DIM}{path}{RESET}")

        if deps:
            print(f"\n  Imports ({len(deps)}):")
            for i, d in enumerate(deps[:6]):
                conn = "└──" if i == min(5, len(deps) - 1) else "├──"
                print(f"   {DIM}{conn}{RESET} {BLUE}{_basename(d)}{RESET}")
            if len(deps) > 6:
                print(f"   {DIM}└── ...{len(deps)-6} more{RESET}")

        if rdeps:
            print(f"\n  Imported by ({len(rdeps)}):")
            for i, d in enumerate(rdeps[:6]):
                conn = "└──" if i == min(5, len(rdeps) - 1) else "├──"
                print(f"   {DIM}{conn}{RESET} {MAGENTA}{_basename(d)}{RESET}")
            if len(rdeps) > 6:
                print(f"   {DIM}└── ...{len(rdeps)-6} more{RESET}")

        _hr("·", 50)

    print(f"\n{BOLD}{'═' * 62}{RESET}\n")


def print_impact_report(report: ImpactReport):
    """Prints a detailed impact analysis for a single file."""
    rc = _risk_color(report.risk_level)
    icon = _risk_icon(report.risk_level)

    print(f"\n{BOLD}{'═' * 62}{RESET}")
    print(f"{BOLD}{CYAN}  🔬 IMPACT ANALYSIS{RESET}")
    print(f"{BOLD}{'═' * 62}{RESET}")

    print(f"\n  Target:  {BOLD}{WHITE}{_basename(report.target)}{RESET}")
    print(f"  Path:    {DIM}{report.target}{RESET}")
    print(f"  Lang:    {CYAN}{report.language}{RESET}")

    # ── Impact score banner ────────────────────────────────────────
    _header("IMPACT SCORE", "💥")
    print(f"\n  {rc}{BOLD}{'█' * min(report.impact_score, 40)}{RESET}"
          f"  {rc}{BOLD}{report.impact_score}{RESET}  files affected")

    print(f"\n  {'Direct dependents:':<28} {BOLD}{len(report.direct_dependents)}{RESET}")
    print(f"  {'Transitive dependents:':<28} {BOLD}{len(report.transitive_dependents)}{RESET}")
    print(f"\n  Risk:  {rc}{BOLD}{icon}  {report.risk_level.upper()}{RESET}")

    # ── What it imports ────────────────────────────────────────────
    _tree_list(report.direct_imports, "This file imports", BLUE)

    # ── Who imports it ─────────────────────────────────────────────
    _tree_list(report.direct_dependents, "Directly imported by", MAGENTA)

    # ── Transitive consumers ───────────────────────────────────────
    if report.transitive_dependents:
        _header("TRANSITIVE IMPACT — Files that break if target breaks", "🌊")
        _tree_list(report.transitive_dependents, "All affected files", YELLOW, max_show=15)

    # ── Affected systems ───────────────────────────────────────────
    if report.affected_summary:
        _header("AFFECTED SYSTEMS", "🏗️")
        for i, system in enumerate(report.affected_summary, 1):
            print(f"  {rc}{i}.{RESET} {system}")

    print(f"\n{BOLD}{'═' * 62}{RESET}\n")


def print_file_relationships(graph: DependencyGraph, path: str):
    """Prints the simple tree view of a single file's direct relationships."""
    name = _basename(path)
    deps = graph.dependencies(path)
    rdeps = graph.dependents(path)
    score = graph.impact_score(path)
    risk = graph.risk_level(path)
    rc = _risk_color(risk)

    print(f"\n{BOLD}{'─' * 50}{RESET}")
    print(f"{BOLD}{WHITE}{name}{RESET}")
    print(f"{DIM}{path}{RESET}")

    if deps:
        print(f"\n  Imports:")
        for i, d in enumerate(deps):
            conn = "└──" if i == len(deps) - 1 else "├──"
            print(f"   {DIM}{conn}{RESET} {BLUE}{_basename(d)}{RESET}")

    if rdeps:
        print(f"\n  Imported by:")
        for i, d in enumerate(rdeps):
            conn = "└──" if i == len(rdeps) - 1 else "├──"
            print(f"   {DIM}{conn}{RESET} {MAGENTA}{_basename(d)}{RESET}")

    print(f"\n  Impact score: {rc}{BOLD}{score}{RESET}  |  Risk: {rc}{BOLD}{risk}{RESET}")
    print(f"{BOLD}{'─' * 50}{RESET}\n")
