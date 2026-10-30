import os
import shutil
import sys
from git import Repo, InvalidGitRepositoryError, GitCommandError


CACHE_DIR = os.path.join(os.getcwd(), ".repo_cache")

# Error substrings that indicate a network/DNS problem (not corruption)
_NETWORK_ERRORS = (
    "Could not resolve host",
    "unable to access",
    "Connection refused",
    "Connection timed out",
    "SSL",
    "Network is unreachable",
    "Failed to connect",
)


def _is_network_error(exc: Exception) -> bool:
    msg = str(exc)
    return any(phrase in msg for phrase in _NETWORK_ERRORS)


def _is_valid_git_repo(path: str) -> bool:
    try:
        Repo(path)
        return True
    except (InvalidGitRepositoryError, Exception):
        return False


def parse_github_url(url: str) -> tuple[str | None, str | None]:
    """Parses a GitHub URL or owner/repo format and returns (owner, repo)."""
    url = url.strip().rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]

    if url.startswith("https://github.com/") or url.startswith("http://github.com/"):
        parts = url.split("/")
        if len(parts) >= 5:
            return parts[3], parts[4]
    elif url.startswith("git@github.com:"):
        path = url.split(":", 1)[1]
        parts = path.split("/")
        if len(parts) == 2:
            return parts[0], parts[1]
    elif "/" in url and not url.startswith("http"):
        parts = url.split("/")
        if len(parts) == 2:
            return parts[0], parts[1]

    return None, None


def clone_repository(repo_url: str, dest_dir: str = None, no_pull: bool = False) -> str:
    """
    Clones a repository to a local cache directory and returns its path.

    Behaviour:
      - If already cached and valid:
          → Try git pull to get latest changes
          → On network error: warn and use the cached version (never delete it)
          → On corruption (not a valid git repo): delete and re-clone
      - If not cached:
          → Clone fresh; raise a clear error on network failure
      - no_pull=True: skip the pull step entirely, always use cached copy

    Raises:
        SystemExit on unrecoverable clone failure (no cache to fall back to)
    """
    if not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR)

    repo_name = repo_url.rstrip("/").split("/")[-1]
    if repo_name.endswith(".git"):
        repo_name = repo_name[:-4]

    target_path = dest_dir or os.path.join(CACHE_DIR, repo_name)

    # ── Already cached ────────────────────────────────────────────────────────
    if os.path.exists(target_path):
        if not _is_valid_git_repo(target_path):
            # Corrupted directory — safe to remove and re-clone
            print(f"⚠️  Cached directory is not a valid git repo. Removing and re-cloning...")
            shutil.rmtree(target_path)
            # Fall through to clone below
        else:
            if no_pull:
                print(f"✔  Using cached repository at {target_path} (--no-pull)")
                return target_path

            print(f"✔  Repository cached at {target_path}. Pulling latest changes...")
            try:
                repo = Repo(target_path)
                repo.remotes.origin.pull()
                print("   Pull successful.")
                return target_path

            except GitCommandError as e:
                if _is_network_error(e):
                    print(
                        f"\n⚠️  Network error during pull (no internet connection?).\n"
                        f"   Using cached version — it may be slightly out of date.\n"
                        f"   Run with --no-pull to suppress this message.\n"
                    )
                    return target_path
                else:
                    # Non-network git error — treat as corruption
                    print(f"⚠️  Pull failed with git error: {e}")
                    print("   Removing corrupted cache and re-cloning...")
                    shutil.rmtree(target_path)
                    # Fall through to clone below

            except Exception as e:
                if _is_network_error(e):
                    print(
                        f"\n⚠️  Network error during pull.\n"
                        f"   Using cached version at {target_path}.\n"
                    )
                    return target_path
                else:
                    print(f"⚠️  Unexpected error during pull: {e}")
                    print("   Using cached version as fallback.")
                    return target_path

    # ── Fresh clone ───────────────────────────────────────────────────────────
    print(f"⬇  Cloning {repo_url} → {target_path} ...")
    try:
        Repo.clone_from(repo_url, target_path)
        return target_path

    except GitCommandError as e:
        if _is_network_error(e):
            print(
                f"\n❌ Cannot clone repository — network unreachable.\n"
                f"   (DNS error: could not resolve github.com)\n\n"
                f"Suggestions:\n"
                f"  1. Check your internet connection.\n"
                f"  2. If you have a local copy, use:  --local /path/to/repo\n"
                f"  3. Clone manually first, then re-run.\n",
                file=sys.stderr,
            )
        else:
            print(
                f"\n❌ Clone failed: {e}\n"
                f"   The repository may be private or the URL may be incorrect.\n"
                f"   If it is private, clone it manually and use: --local /path/to/repo\n",
                file=sys.stderr,
            )
        sys.exit(1)

    except Exception as e:
        print(f"\n❌ Unexpected clone error: {e}", file=sys.stderr)
        sys.exit(1)
