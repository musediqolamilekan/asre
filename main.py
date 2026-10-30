#!/usr/bin/env python3
"""
asre — Repository Intelligence Layer
Usage:
    python main.py <github_url_or_owner/repo> [options]
"""

import argparse
import json
import sys
import os

from intelligence.cloner import clone_repository, parse_github_url
from intelligence.scanner import scan_repository, to_dict
from intelligence.dependency_graph import build_dependency_graph
from intelligence.file_profile import build_file_profiles, get_profile
from intelligence.query_engine import query_codebase
from intelligence.git_analyzer import get_file_change_counts, get_file_last_modified
from repair.incident_mapper import build_repair_context, load_incident
from repair.patch_planner import load_patch_plan, validate_patch_plan
from repair.patch_executor import execute_patch_plan
from repair.repair_runs import save_repair_run
from reporting.reporter import print_report
from reporting.graph_reporter import (
    print_graph_overview,
    print_impact_report,
    print_file_relationships,
)
from reporting.profile_reporter import (
    print_who_uses,
    print_file_profile,
    print_query_results,
)


def _needs_graph(args) -> bool:
    return any([
        args.graph,
        args.impact,
        args.relationships,
        args.list_critical,
        args.who_uses,
        args.profile,
        args.query,
        args.all_profiles,
        args.incident,
        args.patch_plan,
        args.verify_patch_plan,
        args.repair_run_dir,
    ])


def _fuzzy_find(nodes: list[str], query: str) -> list[str]:
    """Returns nodes where query is a substring of the path."""
    return [n for n in nodes if query.lower() in n.lower()]


def main():
    parser = argparse.ArgumentParser(
        prog="asre",
        description="🔍 Repository Intelligence Layer — deep code analysis powered by Tree-sitter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py pallets/click
  python main.py django/django --graph
  python main.py django/django --who-uses models.py
  python main.py django/django --profile core.py
  python main.py django/django --query "authentication error"
  python main.py django/django --list-critical
  python main.py --local ./my-project --all-profiles
        """
    )

    # ── Positional ─────────────────────────────────────────────────
    parser.add_argument(
        "repo",
        nargs="?",
        help="GitHub URL or owner/repo (e.g. 'django/django')",
    )
    parser.add_argument(
        "--local",
        metavar="PATH",
        help="Scan a local directory instead of cloning",
    )

    # ── Dependency graph ───────────────────────────────────────────
    graph_group = parser.add_argument_group("Dependency Graph")
    graph_group.add_argument(
        "--graph",
        action="store_true",
        help="Show CODE RELATIONSHIP GRAPH overview",
    )
    graph_group.add_argument(
        "--impact",
        metavar="FILE",
        help="Impact analysis: what breaks if FILE breaks?",
    )
    graph_group.add_argument(
        "--relationships",
        metavar="FILE",
        help="Show direct import relationships for FILE",
    )
    graph_group.add_argument(
        "--list-critical",
        action="store_true",
        help="Ranked list of all files by impact score",
    )

    # ── Reverse dependency / profiles ──────────────────────────────
    profile_group = parser.add_argument_group("Reverse Dependency & File Profiles")
    profile_group.add_argument(
        "--who-uses",
        metavar="FILE",
        help="Reverse dependency tree: who imports FILE?",
    )
    profile_group.add_argument(
        "--profile",
        metavar="FILE",
        help="Full intelligence profile for FILE (imports, symbols, risk, JSON)",
    )
    profile_group.add_argument(
        "--all-profiles",
        action="store_true",
        help="Export full profiles for every file as JSON (use with --output)",
    )

    # ── Query engine ───────────────────────────────────────────────
    query_group = parser.add_argument_group("Query Engine")
    query_group.add_argument(
        "--query",
        metavar="TEXT",
        help="'What part of the codebase matters for this problem?' — keyword or error message",
    )

    incident_group = parser.add_argument_group("Incident Context")
    incident_group.add_argument(
        "--incident",
        metavar="JSON",
        help="Load a normalized production incident JSON payload",
    )
    incident_group.add_argument(
        "--explain-context",
        action="store_true",
        help="Print deterministic repository evidence for --incident as JSON",
    )
    incident_group.add_argument(
        "--patch-plan",
        metavar="JSON",
        help="Validate a structured patch plan against the incident repair context",
    )
    incident_group.add_argument(
        "--verify-patch-plan",
        action="store_true",
        help="Apply a validated plan in a temporary Git worktree and run its allowlisted tests",
    )
    incident_group.add_argument(
        "--repair-run-dir",
        metavar="DIR",
        help="Write auditable incident, context, plan, and verification artifacts under DIR",
    )

    # ── Output ─────────────────────────────────────────────────────
    out_group = parser.add_argument_group("Output")
    out_group.add_argument(
        "--json",
        action="store_true",
        help="Output full intelligence scan as JSON",
    )
    out_group.add_argument(
        "--output",
        metavar="FILE",
        help="Save JSON report to a file",
    )
    out_group.add_argument(
        "--no-pull",
        action="store_true",
        help="Skip git pull if repo is already cached",
    )

    args = parser.parse_args()

    if (args.explain_context or args.patch_plan or args.verify_patch_plan or args.repair_run_dir) and not args.incident:
        parser.error("incident context options require --incident")
    if args.verify_patch_plan and not args.patch_plan:
        parser.error("--verify-patch-plan requires --patch-plan")

    if not args.repo and not args.local:
        parser.print_help()
        sys.exit(1)

    repo_path = None
    repo_url = ""

    # ── Resolve repo path ─────────────────────────────────────────
    if args.local:
        repo_path = os.path.abspath(args.local)
        if not os.path.isdir(repo_path):
            print(f"Error: '{repo_path}' is not a valid directory.", file=sys.stderr)
            sys.exit(1)
        print(f"\n📂 Scanning local repository: {repo_path}")
    else:
        repo_input = args.repo
        owner, repo_name = parse_github_url(repo_input)
        if not owner:
            print(f"Error: Could not parse repository '{repo_input}'.", file=sys.stderr)
            sys.exit(1)

        repo_url = f"https://github.com/{owner}/{repo_name}"
        print(f"\n🌐 Target: {repo_url}")
        repo_path = clone_repository(repo_url, no_pull=args.no_pull)
        print(f"✅ Repository ready at: {repo_path}\n")

    # ── Run intelligence scan ─────────────────────────────────────
    print("🧠 Running intelligence scan...\n")
    intel = scan_repository(repo_path, repo_url=repo_url, verbose=True)
    ecosystem = intel.ecosystem_context
    if ecosystem and ecosystem.detected_frameworks:
        print(f"   Detected frameworks: {', '.join(ecosystem.detected_frameworks)}")

    # ── Build dependency graph + profiles (if any graph flag set) ──
    graph = None
    profiles = None

    if _needs_graph(args):
        print("\n🕸️  Building dependency graph...")
        print("   → Applying ecosystem module aliases (PSR-4 / package imports / path maps)")
        graph = build_dependency_graph(intel)
        gstats = graph.stats()
        print(f"   {gstats['total_nodes']} nodes, {gstats['total_edges']} edges resolved")

        print("📋 Building file profiles & risk scores...")
        print("   → Collecting git file change history (last 90 days)...")
        file_changes  = get_file_change_counts(repo_path, days=90)
        file_modified = get_file_last_modified(repo_path)
        print(f"   → {len(file_changes)} files with recent git activity")
        profiles = build_file_profiles(graph, intel, file_changes, file_modified)
        print(f"   {len(profiles)} profiles computed\n")

    # ── Standard output (no flags = full repo report) ─────────────
    if args.output or args.json:
        result = to_dict(intel)

        if args.all_profiles and profiles:
            result["file_profiles"] = {
                path: p.to_dict() for path, p in profiles.items()
            }

        json_str = json.dumps(result, indent=2, default=str)

        if args.output:
            with open(args.output, "w") as f:
                f.write(json_str)
            print(f"\n💾 JSON report saved to: {args.output}")

        if args.json and not args.output:
            print(json_str)
        else:
            print_report(intel)
    else:
        print_report(intel)

    if graph is None:
        return

    all_nodes = graph.all_nodes()

    # ── Graph overview ────────────────────────────────────────────
    if args.graph:
        print_graph_overview(graph)

    # ── Impact analysis ───────────────────────────────────────────
    if args.impact:
        matches = _fuzzy_find(all_nodes, args.impact)
        if not matches:
            print(f"\n⚠️  No file matching '{args.impact}' found. Try a partial path.")
        else:
            for m in matches[:3]:
                print_impact_report(graph.get_impact_report(m))

    # ── Relationships ─────────────────────────────────────────────
    if args.relationships:
        matches = _fuzzy_find(all_nodes, args.relationships)
        if not matches:
            print(f"\n⚠️  No file matching '{args.relationships}' found.")
        else:
            for m in matches[:5]:
                print_file_relationships(graph, m)

    # ── List critical ─────────────────────────────────────────────
    if args.list_critical:
        from intelligence.risk_scorer import risk_icon
        # Use 0-100 risk scores from profiles
        ranked = sorted(profiles.values(), key=lambda p: p.risk_score, reverse=True)
        ranked = [p for p in ranked if p.risk_score > 0]
        if not ranked:
            print("\n  No files with risk scores > 0 found.")
        else:
            print(f"\n{'─'*65}")
            print(f"  {'File':<42} {'Score':>5}  {'Risk':<10}  Consumers")
            print(f"{'─'*65}")
            for p in ranked[:50]:
                icon = risk_icon(p.risk_score)
                name = p.basename[:40]
                print(f"  {name:<42} {p.risk_score:>5}  {icon} {p.risk_label:<8}  {p.transitive_impact}")
            print(f"{'─'*65}\n")

    # ── Who uses (reverse dependency) ────────────────────────────
    if args.who_uses:
        matched = get_profile(profiles, args.who_uses)
        if not matched:
            print(f"\n⚠️  No file matching '{args.who_uses}' found.")
        else:
            for p in matched[:3]:
                print_who_uses(p)

    # ── Full file profile ─────────────────────────────────────────
    if args.profile:
        matched = get_profile(profiles, args.profile)
        if not matched:
            print(f"\n⚠️  No file matching '{args.profile}' found.")
        else:
            for p in matched[:2]:
                print_file_profile(p)

    # ── All profiles as JSON ──────────────────────────────────────
    if args.all_profiles and not args.output:
        all_data = {path: p.to_dict() for path, p in profiles.items()}
        print(json.dumps(all_data, indent=2, default=str))

    # ── Query engine ──────────────────────────────────────────────
    if args.query:
        results = query_codebase(profiles, args.query)
        print_query_results(results, args.query)

    repair_context = None
    patch_plan = None
    validation = None
    execution = None
    if args.explain_context or args.patch_plan or args.verify_patch_plan or args.repair_run_dir:
        try:
            incident = load_incident(args.incident)
        except ValueError as exc:
            parser.error(str(exc))
        repair_context = build_repair_context(incident, graph, profiles, repo_path)

    if args.explain_context:
        print(json.dumps(repair_context.to_dict(), indent=2, default=str))

    if args.patch_plan:
        try:
            patch_plan = load_patch_plan(args.patch_plan)
        except ValueError as exc:
            parser.error(str(exc))
        validation = validate_patch_plan(patch_plan, repair_context)
        print(json.dumps({
            "patch_plan": patch_plan.to_dict(),
            "validation": validation.to_dict(),
        }, indent=2, default=str))
        if args.verify_patch_plan:
            execution = execute_patch_plan(patch_plan, repair_context)
            print(json.dumps({"execution": execution.to_dict()}, indent=2, default=str))

    if args.repair_run_dir:
        try:
            repair_run = save_repair_run(
                args.repair_run_dir,
                repair_context,
                plan=patch_plan,
                validation=validation,
                execution=execution,
            )
        except OSError as exc:
            parser.error(f"failed to write repair run: {exc}")
        print(json.dumps({"repair_run": repair_run.to_dict()}, indent=2, default=str))


if __name__ == "__main__":
    main()
