"""Pretty-prints a RepoIntelligence result to the terminal."""
from intelligence.models import RepoIntelligence

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
MAGENTA= "\033[95m"
BLUE   = "\033[94m"


def bar(pct: float, width: int = 30) -> str:
    filled = int(pct / 100 * width)
    return f"{GREEN}{'█' * filled}{DIM}{'░' * (width - filled)}{RESET}"


def hr(char="─", width=60):
    print(f"{DIM}{char * width}{RESET}")


def header(title: str):
    print(f"\n{BOLD}{CYAN}{title}{RESET}")
    hr()


def print_report(intel: RepoIntelligence):
    s = intel

    # ── Title ──────────────────────────────────────────────────────
    print(f"\n{BOLD}{'═' * 60}{RESET}")
    print(f"{BOLD}{CYAN}  🔍 REPOSITORY INTELLIGENCE REPORT{RESET}")
    url = s.repo_url or s.repo_path
    print(f"{BOLD}  {url}{RESET}")
    print(f"{BOLD}{'═' * 60}{RESET}")

    # ── Summary ────────────────────────────────────────────────────
    header("📊  SUMMARY")
    total_mb = round(s.total_size_bytes / (1024 * 1024), 2)
    print(f"  {'Files:':<22} {BOLD}{s.total_files:,}{RESET}")
    print(f"  {'Lines of code:':<22} {BOLD}{s.total_lines:,}{RESET}")
    print(f"  {'Total size:':<22} {BOLD}{total_mb} MB{RESET}")

    analyzed = [f for f in s.file_analyses if f.language != "unknown"]
    print(f"  {'Analyzed files:':<22} {BOLD}{len(analyzed):,}{RESET}")
    print(f"  {'TODOs / FIXMEs:':<22} {BOLD}{len(s.todos):,}{RESET}")

    # ── Git Info ───────────────────────────────────────────────────
    gi = s.git_info
    if gi and "error" not in gi:
        header("🌿  GIT METADATA")
        print(f"  {'Branch:':<22} {BOLD}{gi.get('default_branch', 'N/A')}{RESET}")
        print(f"  {'Total commits:':<22} {BOLD}{gi.get('total_commits', 'N/A'):,}{RESET}")
        print(f"  {'Branches:':<22} {BOLD}{gi.get('total_branches', 'N/A')}{RESET}")
        print(f"  {'Tags:':<22} {BOLD}{gi.get('total_tags', 'N/A')}{RESET}")
        print(f"  {'Last commit:':<22} {BOLD}[{gi.get('last_commit_sha')}]{RESET} {gi.get('last_commit_message', '')[:50]}")
        print(f"  {'Last author:':<22} {BOLD}{gi.get('last_commit_author', 'N/A')}{RESET}")
        print(f"  {'Date:':<22} {DIM}{gi.get('last_commit_date', 'N/A')}{RESET}")

        contribs = gi.get("top_contributors", [])
        if contribs:
            print(f"\n  {BOLD}Top Contributors:{RESET}")
            for email, count in contribs[:5]:
                print(f"    {count:>5} commits  {DIM}{email}{RESET}")

    # ── Languages ──────────────────────────────────────────────────
    if s.language_stats:
        header("📝  LANGUAGE BREAKDOWN")
        for lang, data in s.language_stats.items():
            pct = data["percentage"]
            kb = round(data["bytes"] / 1024, 1)
            print(f"  {lang:<20} {bar(pct)} {BOLD}{pct:>6.2f}%{RESET}  {DIM}{kb} KB{RESET}")

    # ── Dependencies ───────────────────────────────────────────────
    if s.dependencies:
        header("📦  DETECTED PACKAGE MANAGERS")
        for dep in s.dependencies:
            print(f"  {GREEN}✓{RESET}  {dep}")

    # ── Symbols ────────────────────────────────────────────────────
    total_fns = sum(len(f.functions) for f in s.file_analyses)
    total_cls = len(set(s.all_classes))
    total_iface = len(set(s.all_interfaces))
    total_struct = len(set(s.all_structs))

    header("🔣  CODE SYMBOLS")
    print(f"  {'Functions/methods:':<28} {BOLD}{total_fns:,}{RESET}")
    print(f"  {'Classes:':<28} {BOLD}{total_cls:,}{RESET}")
    print(f"  {'Interfaces:':<28} {BOLD}{total_iface:,}{RESET}")
    print(f"  {'Structs:':<28} {BOLD}{total_struct:,}{RESET}")

    if s.top_functions:
        print(f"\n  {BOLD}Most common symbol names:{RESET}")
        for fn, count in s.top_functions[:10]:
            trunc = fn[:50].replace("\n", " ")
            print(f"    {YELLOW}{trunc:<50}{RESET}  ×{count}")

    if s.all_classes:
        print(f"\n  {BOLD}Classes ({min(len(s.all_classes), 20)} of {len(s.all_classes)}):{RESET}")
        shown = sorted(set(s.all_classes))[:20]
        cols = [shown[i::2] for i in range(2)]
        for row in zip(*cols):
            print(f"    {MAGENTA}{row[0]:<30}{RESET}  {MAGENTA}{row[1] if len(row) > 1 else ''}{RESET}")

    # ── TODOs ──────────────────────────────────────────────────────
    if s.todos:
        header(f"🗒️   TODOs & FIXMEs  ({len(s.todos)} total)")
        counts = {}
        for t in s.todos:
            counts[t["type"]] = counts.get(t["type"], 0) + 1
        for kind, cnt in sorted(counts.items(), key=lambda x: x[1], reverse=True):
            color = RED if kind == "FIXME" else YELLOW
            print(f"  {color}{kind:<10}{RESET}  {cnt}")

        print(f"\n  {BOLD}Sample TODOs:{RESET}")
        for t in s.todos[:8]:
            color = RED if t["type"] == "FIXME" else YELLOW
            print(f"  {color}[{t['type']}]{RESET} {t['message'][:60]}")
            print(f"    {DIM}{t['file']}:{t['line']}{RESET}")

    # ── Top Files ──────────────────────────────────────────────────
    header("📁  TOP FILES BY SIZE")
    top_files = sorted(s.file_analyses, key=lambda f: f.size_bytes, reverse=True)[:10]
    for fa in top_files:
        kb = round(fa.size_bytes / 1024, 1)
        print(f"  {kb:>8.1f} KB  {DIM}{fa.path}{RESET}")

    print(f"\n{BOLD}{'═' * 60}{RESET}\n")
