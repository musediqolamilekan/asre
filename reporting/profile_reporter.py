"""
Profile Reporter — terminal renderer for FileProfile and QueryMatch results.

Outputs:
  - Reverse dependency tree ("Who uses this file?")
  - Full file profile with all intelligence data
  - Query results ("What part of the codebase matters for this problem?")
"""

import os
from intelligence.file_profile import FileProfile
from intelligence.query_engine import QueryMatch
from intelligence.risk_scorer import risk_color_code, risk_icon, risk_label, ScoreBreakdown

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
ORANGE  = "\033[38;5;208m"


def _hr(char="─", width=62):
    print(f"{DIM}{char * width}{RESET}")


def _section(title: str, icon: str = ""):
    sep = f"  {icon}  " if icon else "  "
    print(f"\n{BOLD}{CYAN}{sep}{title}{RESET}")
    _hr()


def _risk_bar(score: int, max_score: int = 90, width: int = 30) -> str:
    rc = risk_color_code(score)
    filled = int(score / max(max_score, 1) * width)
    empty = width - filled
    return f"{rc}{'█' * filled}{DIM}{'░' * empty}{RESET}"


def _tree(items: list[str], color: str = WHITE, indent: int = 3, max_show: int = 12):
    """Renders a list as a tree with ├── / └── connectors."""
    shown = items[:max_show]
    for i, item in enumerate(shown):
        is_last = (i == len(shown) - 1) and len(items) <= max_show
        conn = "└──" if is_last else "├──"
        name = os.path.basename(item)
        print(f"{' ' * indent}{DIM}{conn}{RESET} {color}{name}{RESET}  {DIM}{item}{RESET}")
    if len(items) > max_show:
        remaining = len(items) - max_show
        print(f"{' ' * indent}{DIM}└── ...and {remaining} more file{'s' if remaining > 1 else ''}{RESET}")


def print_score_breakdown(breakdown: ScoreBreakdown):
    """
    Prints the deterministic score breakdown table.

    Impact Score: 38

    Direct dependents:       3  →  +15
    Transitive dependents:   5  →  +10
    Recent changes (90d):    2  →  +6
    Public symbols:          1  →  +1
    ────────────────────────────────────
    Total:                       32 / 90
    """
    rc = risk_color_code(breakdown.total)
    icon = risk_icon(breakdown.total)
    max_p = breakdown.max_possible

    print(f"\n  {rc}{BOLD}Impact Score: {breakdown.total}{RESET}  {DIM}(max {max_p}){RESET}  {rc}{icon} {breakdown.label}{RESET}\n")

    col_name  = 26
    col_raw   = 6
    col_arrow = 4

    for c in breakdown.components:
        rc_c = rc if c.points > 0 else DIM
        name_str  = f"{c.name}:{'':<1}"
        raw_str   = f"{c.raw_value}"
        pts_str   = f"+{c.points}" if c.points > 0 else "+0"
        cap_note  = f"  {DIM}(capped at {c.cap}){RESET}" if c.raw_value * c.weight > c.cap else ""
        print(
            f"  {WHITE}{name_str:<{col_name}}{RESET}"
            f"  {BOLD}{raw_str:>{col_raw}}{RESET}"
            f"  {DIM}×{c.weight:>2}  →{RESET}"
            f"  {rc_c}{BOLD}{pts_str:>4}{RESET}"
            f"{cap_note}"
        )

    print(f"  {DIM}{'─' * 46}{RESET}")
    print(f"  {'Total:':<{col_name}}  {' ':>{col_raw}}         {rc}{BOLD}{breakdown.total:>4} / {max_p}{RESET}")
    bar = _risk_bar(breakdown.total, max_score=max_p, width=36)
    print(f"  {bar}")
    print(f"\n  {DIM}Each component = raw_value × weight, capped at its maximum.{RESET}")
    print(f"  {DIM}Thresholds: Critical ≥65 · High ≥40 · Medium ≥20 · Low <20{RESET}")



def print_who_uses(profile: FileProfile):
    """
    Answers: "Who uses this file?"
    Displays the reverse dependency tree + impact score.
    """
    rc = risk_color_code(profile.risk_score)
    icon = risk_icon(profile.risk_score)

    print(f"\n{BOLD}{'═' * 62}{RESET}")
    print(f"{BOLD}{CYAN}  🔍 REVERSE DEPENDENCY — Who uses this file?{RESET}")
    print(f"{BOLD}{'═' * 62}{RESET}")

    print(f"\n  {BOLD}{WHITE}{profile.basename}{RESET}")
    print(f"  {DIM}{profile.file}{RESET}")
    print(f"  {CYAN}{profile.language}{RESET}  ·  {profile.lines:,} lines  ·  {round(profile.size_bytes/1024, 1)} KB")

    # ── Who imports this file ──────────────────────────────────────
    _section("USED BY (direct importers)", "📥")
    if profile.imported_by:
        _tree(profile.imported_by, color=MAGENTA)
    else:
        print(f"  {DIM}No files directly import this file.{RESET}")

    # ── Transitive consumers ───────────────────────────────────────
    if profile.transitive_consumers:
        _section("ALL DOWNSTREAM CONSUMERS (transitive)", "🌊")
        _tree(profile.transitive_consumers, color=YELLOW, max_show=15)

    # ── Impact score breakdown ─────────────────────────────────────
    _section("IMPACT SCORE & BREAKDOWN", "💥")
    if profile.score_breakdown:
        print_score_breakdown(profile.score_breakdown)
    else:
        print(f"  {DIM}Score breakdown not available.{RESET}")

    print(f"\n  {'Direct importers:':<28} {BOLD}{profile.direct_impact}{RESET}")
    print(f"  {'Transitive consumers:':<28} {BOLD}{profile.transitive_impact}{RESET}")
    print(f"  {'Coupling (imports out):':<28} {BOLD}{profile.coupling_score}{RESET}")
    if profile.recent_changes:
        print(f"  {'Git commits (90d):':<28} {BOLD}{profile.recent_changes}{RESET}")
    if profile.last_modified:
        print(f"  {'Last changed:':<28} {DIM}{profile.last_modified}{RESET}")

    print(f"\n{BOLD}{'═' * 62}{RESET}\n")


def print_file_profile(profile: FileProfile):
    """
    Prints the complete intelligence profile for a file.
    """
    rc = risk_color_code(profile.risk_score)
    icon = risk_icon(profile.risk_score)

    print(f"\n{BOLD}{'═' * 62}{RESET}")
    print(f"{BOLD}{CYAN}  📋 FILE PROFILE{RESET}")
    print(f"{BOLD}{'═' * 62}{RESET}")

    # ── Header ─────────────────────────────────────────────────────
    print(f"\n  {BOLD}{WHITE}{profile.basename}{RESET}")
    print(f"  {DIM}{profile.file}{RESET}")
    print(f"  {CYAN}{profile.language}{RESET}  ·  {profile.lines:,} lines  ·  {round(profile.size_bytes/1024,1)} KB")

    # ── Risk score breakdown ────────────────────────────────────────
    _section("RISK SCORE BREAKDOWN", "🎯")
    if profile.score_breakdown:
        print_score_breakdown(profile.score_breakdown)
    else:
        rc = risk_color_code(profile.risk_score)
        print(f"\n  {_risk_bar(profile.risk_score)}  {rc}{BOLD}{profile.risk_score}/90{RESET}")

    if profile.last_modified:
        print(f"\n  {'Last git change:':<28} {DIM}{profile.last_modified}{RESET}")


    # ── Imports (what this file depends on) ────────────────────────
    _section(f"IMPORTS ({len(profile.imports)} files)", "📤")
    if profile.imports:
        _tree(profile.imports, color=BLUE)
    else:
        print(f"  {DIM}No internal imports resolved.{RESET}")

    # ── Imported by (reverse deps) ─────────────────────────────────
    _section(f"IMPORTED BY ({profile.direct_impact} files)", "📥")
    if profile.imported_by:
        _tree(profile.imported_by, color=MAGENTA)
    else:
        print(f"  {DIM}Not imported by any other file in this repo.{RESET}")

    # ── Transitive consumers ───────────────────────────────────────
    if profile.transitive_consumers:
        _section(f"TRANSITIVE CONSUMERS ({profile.transitive_impact} files)", "🌊")
        _tree(profile.transitive_consumers, color=YELLOW, max_show=12)

    # ── Functions ──────────────────────────────────────────────────
    if profile.functions:
        _section(f"FUNCTIONS ({len(profile.functions)})", "⚙️")
        shown = profile.functions[:20]
        cols = [shown[i::2] for i in range(2)]
        for row in zip(*cols):
            left = f"{GREEN}{row[0]:<30}{RESET}"
            right = f"{GREEN}{row[1]}{RESET}" if len(row) > 1 else ""
            print(f"  {left}  {right}")
        if len(profile.functions) > 20:
            print(f"  {DIM}...and {len(profile.functions)-20} more{RESET}")

    # ── Classes / Structs / Interfaces ─────────────────────────────
    all_types = profile.classes + profile.interfaces + profile.structs
    if all_types:
        _section(f"TYPES — Classes / Interfaces / Structs ({len(all_types)})", "🏗️")
        for t in all_types[:15]:
            print(f"  {ORANGE}◆  {t}{RESET}")
        if len(all_types) > 15:
            print(f"  {DIM}...and {len(all_types)-15} more{RESET}")

    # ── TODOs ──────────────────────────────────────────────────────
    if profile.todos:
        _section(f"TODOs / FIXMEs ({len(profile.todos)})", "🗒️")
        for t in profile.todos[:6]:
            color = RED if t.get("type") == "FIXME" else YELLOW
            print(f"  {color}[{t.get('type')}]{RESET} {t.get('message','')[:60]}")
            print(f"    {DIM}line {t.get('line')}{RESET}")

    # ── JSON block ─────────────────────────────────────────────────
    _section("MACHINE-READABLE PROFILE", "📦")
    import json
    compact = {
        "file": profile.file,
        "imports": profile.imports,
        "imported_by": profile.imported_by,
        "functions": profile.functions[:15],
        "classes": profile.classes[:10],
        "risk_score": profile.risk_score,
        "risk_label": profile.risk_label,
        "direct_impact": profile.direct_impact,
        "transitive_impact": profile.transitive_impact,
    }
    print(f"\n{DIM}{json.dumps(compact, indent=2)}{RESET}")

    print(f"\n{BOLD}{'═' * 62}{RESET}\n")


def print_query_results(matches: list[QueryMatch], query: str):
    """
    Prints the results of a codebase query:
    "What part of the codebase matters for this problem?"
    """
    print(f"\n{BOLD}{'═' * 62}{RESET}")
    print(f"{BOLD}{CYAN}  🔎 CODEBASE QUERY RESULTS{RESET}")
    print(f"{BOLD}{'═' * 62}{RESET}")
    print(f"\n  Query: {BOLD}\"{query}\"{RESET}")
    print(f"  Found {BOLD}{len(matches)}{RESET} relevant file{'s' if len(matches) != 1 else ''}\n")

    if not matches:
        print(f"  {DIM}No files matched the query. Try a different keyword or module name.{RESET}\n")
        return

    _hr()

    for i, match in enumerate(matches, 1):
        p = match.profile
        rc = risk_color_code(p.risk_score)
        icon = risk_icon(p.risk_score)

        print(f"\n  {BOLD}{WHITE}{i}. {p.basename}{RESET}  {rc}{icon} {p.risk_label}  (risk: {p.risk_score}/100){RESET}")
        print(f"     {DIM}{p.file}{RESET}")
        print(f"     Relevance: {BOLD}{round(match.final_score, 1)}/100{RESET}  ·  {CYAN}{p.language}{RESET}  ·  {p.lines:,} lines")

        # Match reasons
        for reason in match.match_reasons:
            print(f"     {DIM}↳ {reason}{RESET}")

        # Quick snapshot of who uses this
        if p.imported_by:
            names = [os.path.basename(f) for f in p.imported_by[:4]]
            suffix = f" +{len(p.imported_by)-4} more" if len(p.imported_by) > 4 else ""
            print(f"     {MAGENTA}Used by: {', '.join(names)}{suffix}{RESET}")

        # Top functions
        if p.functions:
            shown_fns = p.functions[:5]
            suffix = f" +{len(p.functions)-5} more" if len(p.functions) > 5 else ""
            print(f"     {GREEN}Functions: {', '.join(shown_fns)}{suffix}{RESET}")

        _hr("·", 50)

    print(f"\n{BOLD}{'═' * 62}{RESET}\n")
    print(f"  {DIM}Tip: Run --profile <file> for a deep-dive into any of these files.{RESET}\n")
