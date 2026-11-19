"""
github_explorer — Save GitHub repos and export browse-ready bundles.

No AI calls. The plugin does three things:

1. Shallow-clone a public repo under ~/.local/share/netsentry/repos/.
2. Track what you saved (list, tag, search, delete).
3. Pack the repo into one Markdown bundle (README + manifests + file tree)
   and ship it as a Telegram document so you can paste it into ChatGPT
   yourself.

Nothing to memorise: paste a GitHub link into the chat and you are asked
whether to save it; `/gh` lists the saved repositories as buttons, each with
its own (open, bundle, delete). The typed forms below keep working.

A cloned repository is untrusted content. It is checked out with symlinks
disabled and only regular files that really live inside the clone are read, so
a repo cannot make a bundle carry some other file from this machine.

Commands
--------
/gh                          Saved repositories, as buttons
/gh <URL or owner/repo>      Clone shallow
/gh list [N]                 Last N cloned repos
/gh show <name>              Metadata + README preview
/gh bundle <name>            Send full .md bundle as Telegram document
/gh tag <name> a,b           Tag a repo
/gh search <text>            Search name / tags / language
/gh delete <name>            Remove clone + registry entry
/gh export                   Send the registry as a .md file

Storage
-------
Configured base dir (default ~/.local/share/netsentry/repos/) gets a subfolder:
    ~/.local/share/netsentry/repos/<owner>/<repo>/
Registry at state_dir/repos.json.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import threading
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from ..core.jsonstore import read_json, write_json
from ..core.plugin import Plugin


_GH_URL_RE = re.compile(
    r"^https?://github\.com/"
    r"([\w.-]+)/([\w.-]+?)(?:\.git)?/?$"
)
_GH_SLUG_RE = re.compile(r"^([\w.-]+)/([\w.-]+)$")
# A link as people paste it: the repo page or anything below it (tree, blob…).
_GH_PASTED_RE = re.compile(
    r"^https?://(?:www\.)?github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?(?:[/?#]\S*)?$"
)
# First path segments that are GitHub pages, not accounts.
_GH_NOT_OWNERS = frozenset({
    "about", "apps", "collections", "enterprise", "explore", "features", "login",
    "marketplace", "notifications", "orgs", "pricing", "search", "settings",
    "site", "sponsors", "topics", "trending", "users",
})
_PAGE = 6                   # repositories per button page


def _parse_repo(s: str) -> tuple[str, str] | None:
    s = s.strip()
    for sep in ("?", "#"):
        if sep in s:
            s = s.split(sep, 1)[0]
    m = _GH_URL_RE.fullmatch(s) or _GH_SLUG_RE.fullmatch(s)
    if not m:
        return None
    owner, repo = m.group(1), m.group(2)
    if any(part in {"", ".", ".."} or part.startswith(("-", ".")) for part in (owner, repo)):
        return None
    return owner, repo


def _parse_pasted(text: str) -> tuple[str, str] | None:
    """``(owner, repo)`` when ``text`` is nothing but a link into a GitHub repo."""
    m = _GH_PASTED_RE.fullmatch((text or "").strip())
    if not m or m.group(1).lower() in _GH_NOT_OWNERS:
        return None
    return _parse_repo(f"{m.group(1)}/{m.group(2)}")


def _repo_key(owner: str, repo: str) -> str:
    """Short stable id of a repository, small enough for a button."""
    return hashlib.sha1(f"{owner}/{repo}".lower().encode(),
                        usedforsecurity=False).hexdigest()[:8]


def _clip(text: str, n: int) -> str:
    return text if len(text) <= n else text[: n - 1] + "…"


def _int(text: str, default: int = 0) -> int:
    try:
        return int(text)
    except (TypeError, ValueError):
        return default


_EXT_LANG = {
    ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
    ".tsx": "TypeScript/React", ".jsx": "JavaScript/React",
    ".go": "Go", ".rs": "Rust", ".java": "Java", ".kt": "Kotlin",
    ".rb": "Ruby", ".php": "PHP", ".cs": "C#", ".swift": "Swift",
    ".c": "C", ".cpp": "C++", ".cc": "C++", ".h": "C/C++ header",
    ".hpp": "C++ header", ".sh": "Shell", ".bash": "Shell",
    ".sql": "SQL", ".html": "HTML", ".css": "CSS", ".scss": "Sass",
    ".vue": "Vue", ".svelte": "Svelte", ".dart": "Dart",
    ".lua": "Lua", ".pl": "Perl", ".r": "R", ".m": "Objective-C",
    ".scala": "Scala", ".groovy": "Groovy",
    ".clj": "Clojure", ".ex": "Elixir", ".exs": "Elixir script",
    ".erl": "Erlang", ".hs": "Haskell", ".ml": "OCaml",
    ".nim": "Nim", ".zig": "Zig", ".sol": "Solidity",
    ".yaml": "YAML", ".yml": "YAML", ".toml": "TOML",
    ".json": "JSON", ".xml": "XML", ".md": "Markdown",
    ".tf": "Terraform",
}

_MANIFEST_FILES = [
    "package.json", "pyproject.toml", "setup.py", "setup.cfg",
    "requirements.txt", "Pipfile", "poetry.lock",
    "Cargo.toml", "go.mod", "Gemfile", "composer.json",
    "build.gradle", "pom.xml", "Makefile", "CMakeLists.txt",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".gitlab-ci.yml",
    "tsconfig.json", "next.config.js", "vite.config.ts",
    "yarn.lock", "package-lock.json", "pnpm-lock.yaml",
]


class GithubExplorerPlugin(Plugin):
    COMMANDS = [
        {"command": "gh",
         "description": "📁 GitHub repo: /gh <owner/repo>|list|show|bundle|tag|search|delete|export"},
    ]

    # ─── lifecycle ──────────────────────────────────────────────

    def on_load(self) -> None:
        self._base_dir = Path(os.path.expanduser(
            self.cfg.get("base_dir", "~/.local/share/netsentry/repos")
        )).resolve()
        self._base_dir.mkdir(parents=True, exist_ok=True)
        self._registry_path = Path(self.ctx.state_dir) / "repos.json"
        self._registry_path.parent.mkdir(parents=True, exist_ok=True)
        if not self._registry_path.exists():
            self._registry_path.write_text("[]", encoding="utf-8")
        self._clone_depth = int(self.cfg.get("clone_depth", 50))
        self._max_files_listed = int(self.cfg.get("max_files_listed", 200))
        self._max_readme_chars = int(self.cfg.get("max_readme_chars", 12000))
        self._bundle_max_inline_file_chars = int(
            self.cfg.get("bundle_max_inline_file_chars", 4000)
        )
        self._bundle_inline_extras = self.cfg.get("bundle_inline_extras", [
            "pyproject.toml", "package.json", "Cargo.toml", "go.mod",
            "Makefile", "Dockerfile", "docker-compose.yml",
            "tsconfig.json", "requirements.txt",
        ])
        # Commands run on several worker threads; one load→change→save at a time.
        self._lock = threading.RLock()
        self._offered: dict[str, tuple[str, str]] = {}   # pasted links awaiting a tap
        if self.ctx.events and self.cfg.get("offer_pasted_links", True):
            self.ctx.events.subscribe("telegram.text", self._on_text)

    # ─── registry ───────────────────────────────────────────────

    def _load_reg(self) -> list[dict]:
        # A damaged file is moved aside (repos.json.corrupt), never treated as
        # "no repositories" — the next save would otherwise erase the list.
        entries = read_json(self._registry_path, [])
        return [e for e in entries
                if isinstance(e, dict) and e.get("owner") and e.get("repo")]

    def _save_reg(self, entries: list[dict]) -> None:
        write_json(self._registry_path, entries)

    def _inside_base(self, target: Path) -> bool:
        """True when ``target`` is a folder strictly inside the repos folder."""
        try:
            return self._base_dir in target.resolve().parents
        except OSError:
            return False

    def _remove_clone(self, target: Path) -> None:
        """Delete a clone — but never anything outside the repos folder."""
        if target.exists() and self._inside_base(target):
            shutil.rmtree(target, ignore_errors=True)

    def _resolve(self, entries: list[dict], hint: str) -> dict | None:
        hint = hint.strip()
        if "/" in hint:
            p = _parse_repo(hint)
            if p:
                owner, repo = p
                for e in entries:
                    if e["owner"] == owner and e["repo"] == repo:
                        return e
        matches = [e for e in entries if e["repo"] == hint]
        if len(matches) == 1:
            return matches[0]
        if hint.isdigit():
            i = int(hint)
            if 1 <= i <= len(entries):
                return entries[i - 1]
        return None

    # ─── public API (consumed by the web dashboard) ─────────────

    def api_repos(self) -> list[dict]:
        """Saved repos as rows for the web Library page (newest first)."""
        out: list[dict] = []
        for e in self._load_reg():
            cs = e.get("context_summary", {})
            owner, repo = e.get("owner", ""), e.get("repo", "")
            out.append({
                "owner":      owner,
                "repo":       repo,
                "url":        f"https://github.com/{owner}/{repo}",
                "languages":  [lang for lang, _ in cs.get("languages", [])[:4]],
                "file_count": int(cs.get("file_count", 0)),
                "manifests":  cs.get("manifests", []),
                "tags":       e.get("tags", []),
                "cloned_at":  e.get("cloned_at", ""),
            })
        out.reverse()
        return out

    # ─── dispatch ───────────────────────────────────────────────

    def on_command(self, command: str, args: str, chat_id: int) -> None:
        if command != "/gh":
            return
        args = args.strip()
        if not args:
            self._show(chat_id, None, *self._home_screen(0))
            return

        kw, _, rest = args.partition(" ")
        kw_l = kw.lower()
        rest = rest.strip()

        handlers = {
            "help":   lambda c, _r: self._send_help(c),
            "list":   self._cmd_list,
            "show":   self._cmd_show,
            "bundle": self._cmd_bundle,
            "tag":    self._cmd_tag,
            "search": self._cmd_search,
            "delete": self._cmd_delete,
            "rm":     self._cmd_delete,
            "export": self._cmd_export,
        }
        if kw_l in handlers:
            handlers[kw_l](chat_id, rest)
            return

        # Default: treat whole args as a repo identifier and clone
        parsed = _parse_repo(args)
        if not parsed:
            self._send(chat_id, "❓ Not a recognisable repo URL or owner/repo. Try /gh for help.")
            return
        self._cmd_clone(chat_id, *parsed)

    # ─── subcommands ────────────────────────────────────────────

    def _cmd_clone(self, chat_id: int, owner: str, repo: str) -> None:
        # GitHub names are case-insensitive; folders here are not. Reuse the
        # spelling already saved instead of cloning "Owner/Repo" a second time.
        known = next((e for e in self._load_reg()
                      if e["owner"].lower() == owner.lower()
                      and e["repo"].lower() == repo.lower()), None)
        if known:
            owner, repo = known["owner"], known["repo"]
        target = self._base_dir / owner / repo
        if not target.exists():
            self._send(chat_id, f"📁 Cloning {owner}/{repo}…")
            target.parent.mkdir(parents=True, exist_ok=True)
            url = f"https://github.com/{owner}/{repo}.git"
            try:
                r = subprocess.run(
                    # core.symlinks=false: links in the repo arrive as small
                    # text files instead of pointing somewhere on this machine.
                    ["git", "-c", "core.symlinks=false", "clone",
                     f"--depth={self._clone_depth}", "--no-tags", "--", url, str(target)],
                    capture_output=True, text=True, timeout=180,
                    # Private or misspelt repo: fail, don't wait for a password.
                    env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
                )
            except subprocess.TimeoutExpired:
                self._remove_clone(target)      # a half clone would look "already cloned"
                self._send(chat_id, "❌ Clone timed out.")
                return
            except OSError as e:
                self._send(chat_id, f"❌ Could not run git on this machine: {e}")
                return
            if r.returncode != 0:
                self._remove_clone(target)
                self._send(chat_id, f"❌ Clone failed:\n{r.stderr[-500:]}")
                return
        else:
            self._send(chat_id, "📁 Already cloned. Updating registry only.")

        ctx = self._scan_repo(target)
        now = datetime.now().isoformat(timespec="seconds")
        with self._lock:
            entries = self._load_reg()
            entry = next((e for e in entries
                          if e["owner"] == owner and e["repo"] == repo), None)
            if entry is None:
                entry = {"owner": owner, "repo": repo, "path": str(target),
                         "cloned_at": now, "tags": []}
                entries.append(entry)
            entry["last_seen"] = now
            entry["context_summary"] = {
                "languages":  ctx["languages"],
                "manifests":  ctx["manifests"],
                "file_count": ctx["file_count"],
            }
            self._save_reg(entries)
            idx = entries.index(entry) + 1

        langs = ", ".join(
            f"{language} ({count})" for language, count in ctx["languages"][:4]
        ) or "—"
        manifests = ", ".join(ctx["manifests"][:6]) or "—"
        name, key = self.ctx.name, _repo_key(owner, repo)
        self._send(chat_id,
            f"✅ {owner}/{repo}  →  #{idx}\n"
            f"📍 {target}\n"
            f"📊 {ctx['file_count']} files, langs: {langs}\n"
            f"📦 manifests: {manifests}",
            buttons=[[{"text": "📦 Send the bundle", "callback_data": f"{name}:b:{key}"},
                      {"text": "📁 Repositories", "callback_data": f"{name}:h:0"}]])

    def _cmd_list(self, chat_id: int, rest: str) -> None:
        n = max(1, int(rest)) if rest.isdigit() else 10
        entries = self._load_reg()
        if not entries:
            self._send(chat_id, "📁 No repos cloned yet. /gh <owner/repo> to start.")
            return
        slice_ = entries[-n:]
        lines = [f"📁 Cloned repos (last {len(slice_)} of {len(entries)})", "─" * 25]
        for i, e in enumerate(slice_, start=len(entries) - len(slice_) + 1):
            tags = (" #" + " #".join(e.get("tags", []))) if e.get("tags") else ""
            langs = ", ".join(
                language
                for language, _ in e.get("context_summary", {}).get("languages", [])[:3]
            ) or "?"
            lines.append(f"{i:>2} • {e['owner']}/{e['repo']}{tags}")
            lines.append(f"     {langs}")
        self._send(chat_id, "\n".join(lines))

    def _cmd_show(self, chat_id: int, rest: str) -> None:
        if not rest:
            self._send(chat_id, "Usage: /gh show <name|idx>")
            return
        entries = self._load_reg()
        e = self._resolve(entries, rest)
        if not e:
            self._send(chat_id, f"❌ Not found: {rest}")
            return
        self._show(chat_id, None, *self._repo_screen(e, 0))

    def _details(self, e: dict) -> str:
        target = Path(e["path"])
        tags = (" #" + " #".join(e.get("tags", []))) if e.get("tags") else ""
        head = f"📁 {e['owner']}/{e['repo']}{tags}\n📍 {target}\n"
        if not target.exists():
            return head + "⚠️ Clone missing on disk."
        ctx = self._scan_repo(target)
        readme_preview = (ctx["readme"] or "").strip().split("\n\n", 1)[0]
        if len(readme_preview) > 800:
            readme_preview = readme_preview[:800] + "…"
        langs = ", ".join(
            f"{language} ({count})" for language, count in ctx["languages"][:5]
        ) or "—"
        manifests = ", ".join(ctx["manifests"]) or "—"
        return (head +
                f"📊 {ctx['file_count']} files\n"
                f"💻 {langs}\n"
                f"📦 {manifests}\n\n"
                f"README preview:\n{readme_preview or '(empty)'}")

    def _cmd_bundle(self, chat_id: int, rest: str) -> None:
        if not rest:
            self._send(chat_id, "Usage: /gh bundle <name|idx>")
            return
        entries = self._load_reg()
        e = self._resolve(entries, rest)
        if not e:
            self._send(chat_id, f"❌ Not found: {rest}")
            return
        self._send_bundle(chat_id, e)

    def _send_bundle(self, chat_id: int, e: dict) -> None:
        target = Path(e["path"])
        if not target.exists():
            self._send(chat_id, f"⚠️ Clone missing on disk: {target}")
            return

        ctx = self._scan_repo(target)
        bundle_md = self._build_bundle_md(e, target, ctx)

        tmp = Path(tempfile.gettempdir()) / f"gh-{e['owner']}-{e['repo']}-bundle.md"
        tmp.write_text(bundle_md, encoding="utf-8")

        ok = False
        if hasattr(self.notifier, "send_document"):
            ok = self.notifier.send_document(
                chat_id, str(tmp),
                caption=f"📁 {e['owner']}/{e['repo']} bundle",
                filename=tmp.name,
            )
        try:
            tmp.unlink()
        except OSError:
            pass

        if not ok:
            for chunk in _chunk(bundle_md, 3900):
                self._send(chat_id, chunk)

    def _cmd_tag(self, chat_id: int, rest: str) -> None:
        parts = rest.split(maxsplit=1)
        if len(parts) < 2:
            self._send(chat_id, "Usage: /gh tag <name|idx> <tag1,tag2,...>")
            return
        hint, raw_tags = parts
        tags = [t.strip().lower().replace(" ", "_") for t in raw_tags.split(",") if t.strip()]
        with self._lock:
            entries = self._load_reg()
            e = self._resolve(entries, hint)
            if not e:
                self._send(chat_id, f"❌ Not found: {hint}")
                return
            e["tags"] = tags
            self._save_reg(entries)
        self._send(chat_id, f"🏷 Tags for {e['owner']}/{e['repo']}: {', '.join(tags) or '(none)'}")

    def _cmd_search(self, chat_id: int, rest: str) -> None:
        if not rest:
            self._send(chat_id, "Usage: /gh search <text>")
            return
        q = rest.lower()
        entries = self._load_reg()
        hits = []
        for i, e in enumerate(entries, start=1):
            langs = " ".join(
                language
                for language, _ in e.get("context_summary", {}).get("languages", [])
            )
            blob = f"{e['owner']} {e['repo']} {langs} {' '.join(e.get('tags', []))}".lower()
            if q in blob:
                hits.append((i, e))
        if not hits:
            self._send(chat_id, f"🔍 No matches for '{rest}'")
            return
        lines = [f"🔍 {len(hits)} matches for '{rest}'", "─" * 25]
        for i, e in hits[:30]:
            lines.append(f"{i:>2} • {e['owner']}/{e['repo']}")
        self._send(chat_id, "\n".join(lines))

    def _cmd_delete(self, chat_id: int, rest: str) -> None:
        if not rest:
            self._send(chat_id, "Usage: /gh delete <name|idx>")
            return
        e = self._resolve(self._load_reg(), rest)
        if not e:
            self._send(chat_id, f"❌ Not found: {rest}")
            return
        self._send(chat_id, self._delete(e))

    def _delete(self, e: dict) -> str:
        """Remove a repository from the list and its clone from disk."""
        target = Path(e["path"])
        note = ""
        if target.exists():
            if not self._inside_base(target):
                # The list is only a file; never let it point a delete elsewhere.
                note = (f"\n⚠️ {target} is outside the repositories folder, "
                        "so the folder was left alone.")
            else:
                try:
                    shutil.rmtree(target)
                except OSError as ex:
                    return f"❌ Could not delete {target}: {ex}"
        with self._lock:
            entries = [x for x in self._load_reg()
                       if not (x["owner"] == e["owner"] and x["repo"] == e["repo"])]
            self._save_reg(entries)
        return f"🗑 Deleted {e['owner']}/{e['repo']}{note}"

    def _cmd_export(self, chat_id: int, rest: str) -> None:
        entries = self._load_reg()
        if not entries:
            self._send(chat_id, "📁 Nothing to export.")
            return
        lines = [
            "# GitHub repos — NetSentry export",
            f"_Generated {datetime.now().isoformat(timespec='seconds')} — {len(entries)} entries_",
            "",
        ]
        for i, e in enumerate(entries, start=1):
            tags = (" `#" + "` `#".join(e.get("tags", [])) + "`") if e.get("tags") else ""
            langs = ", ".join(
                language
                for language, _ in e.get("context_summary", {}).get("languages", [])[:5]
            ) or "?"
            lines.append(f"## {i}. {e['owner']}/{e['repo']}{tags}")
            lines.append(f"- **Path:** `{e['path']}`")
            lines.append(f"- **Languages:** {langs}")
            lines.append(f"- **Cloned:** {e.get('cloned_at','?')}")
            lines.append("")
        text = "\n".join(lines)

        tmp = Path(tempfile.gettempdir()) / f"netsentry-gh-library-{datetime.now():%Y%m%d-%H%M}.md"
        tmp.write_text(text, encoding="utf-8")
        ok = False
        if hasattr(self.notifier, "send_document"):
            ok = self.notifier.send_document(
                chat_id, str(tmp),
                caption=f"📁 GitHub repos export ({len(entries)} entries)",
                filename=tmp.name,
            )
        try:
            tmp.unlink()
        except OSError:
            pass

        if not ok:
            for chunk in _chunk(text, 3900):
                self._send(chat_id, chunk)

    # ─── analysis: scan + bundle ────────────────────────────────

    def _scan_repo(self, root: Path) -> dict[str, Any]:
        readme = self._find_and_read_readme(root)
        languages, file_count, file_list = self._scan_files(root)
        manifests = self._find_manifests(root)
        return {
            "readme":       readme,
            "languages":    languages,
            "file_count":   file_count,
            "files_sample": file_list[: self._max_files_listed],
            "manifests":    manifests,
        }

    def _find_and_read_readme(self, root: Path) -> str:
        for name in ("README.md", "README.rst", "README.txt", "README",
                     "readme.md", "Readme.md"):
            text = self._read_repo_file(root, name, self._max_readme_chars)
            if text is not None:
                return text
        return ""

    @staticmethod
    def _read_repo_file(root: Path, name: str, limit: int) -> str | None:
        """Text of a regular file that really lives inside the clone, else None.

        A repository can ship a symlink called README.md (or Makefile…) that
        points at any file on this machine. Following it would put that file
        into a bundle the owner then pastes somewhere, so links are refused.
        """
        p = root / name
        try:
            if p.is_symlink() or not p.is_file():
                return None
            if root.resolve() not in p.resolve().parents:
                return None
            with p.open(encoding="utf-8", errors="replace") as f:
                text = f.read(limit + 1)
        except OSError:
            return None
        return text[:limit] + "\n… [truncated]" if len(text) > limit else text

    def _scan_files(self, root: Path) -> tuple[list[tuple[str, int]], int, list[str]]:
        skip_dirs = {".git", "node_modules", ".venv", "venv", "__pycache__",
                     "dist", "build", "target", ".idea", ".vscode"}
        counts: Counter[str] = Counter()
        files: list[str] = []
        file_count = 0
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in skip_dirs]
            for f in filenames:
                file_count += 1
                ext = Path(f).suffix.lower()
                lang = _EXT_LANG.get(ext)
                if lang:
                    counts[lang] += 1
                rel = str(Path(dirpath).joinpath(f).relative_to(root))
                files.append(rel)
        files.sort()
        return counts.most_common(), file_count, files

    def _find_manifests(self, root: Path) -> list[str]:
        return [name for name in _MANIFEST_FILES if (root / name).exists()]

    def _build_bundle_md(self, entry: dict, root: Path, ctx: dict[str, Any]) -> str:
        out: list[str] = []
        out.append(f"# {entry['owner']}/{entry['repo']} — NetSentry bundle")
        out.append(
            f"_Generated {datetime.now().isoformat(timespec='seconds')} from "
            f"`{entry['path']}` (shallow clone, depth {self._clone_depth})._"
        )
        out.append("")

        out.append("## Summary")
        out.append(f"- **Owner / repo:** `{entry['owner']}/{entry['repo']}`")
        out.append(f"- **Local path:** `{entry['path']}`")
        out.append(f"- **Cloned at:** {entry.get('cloned_at','?')}")
        out.append(f"- **File count:** {ctx['file_count']}")
        if entry.get("tags"):
            out.append(f"- **Tags:** {', '.join(entry['tags'])}")
        out.append("")

        out.append("## Languages")
        if ctx["languages"]:
            for lang, count in ctx["languages"][:12]:
                out.append(f"- {lang}: {count}")
        else:
            out.append("_(no recognised source files)_")
        out.append("")

        out.append("## Manifests detected")
        if ctx["manifests"]:
            for m in ctx["manifests"]:
                out.append(f"- `{m}`")
        else:
            out.append("_(none)_")
        out.append("")

        # Inline interesting small files (manifests / configs)
        inlined = self._inline_extras(root, ctx["manifests"])
        if inlined:
            out.append("## Key files (inlined)")
            for name, body in inlined:
                lang = self._fence_lang(name)
                out.append(f"### `{name}`")
                out.append(f"```{lang}")
                out.append(body)
                out.append("```")
                out.append("")

        out.append("## README")
        out.append("")
        if ctx["readme"]:
            out.append(ctx["readme"])
        else:
            out.append("_(no README found in the repo)_")
        out.append("")

        out.append("## File tree (sample)")
        out.append("```")
        for f in ctx["files_sample"]:
            out.append(f)
        if ctx["file_count"] > len(ctx["files_sample"]):
            out.append(f"… [+{ctx['file_count'] - len(ctx['files_sample'])} more files]")
        out.append("```")
        out.append("")

        return "\n".join(out)

    def _inline_extras(self, root: Path, manifests: list[str]) -> list[tuple[str, str]]:
        """Read a handful of small key files inline. Skip the giant ones."""
        wanted = list(dict.fromkeys(self._bundle_inline_extras + manifests))
        out: list[tuple[str, str]] = []
        for name in wanted:
            text = self._read_repo_file(root, name, self._bundle_max_inline_file_chars)
            if text is not None:
                out.append((name, text))
        return out

    @staticmethod
    def _fence_lang(filename: str) -> str:
        ext = Path(filename).suffix.lower()
        return {
            ".py": "python", ".js": "javascript", ".ts": "typescript",
            ".json": "json", ".toml": "toml", ".yaml": "yaml", ".yml": "yaml",
            ".md": "markdown", ".sh": "bash", ".go": "go", ".rs": "rust",
            ".java": "java", ".rb": "ruby", ".php": "php",
        }.get(ext, "")

    # ─── button screens ─────────────────────────────────────────

    def _home_screen(self, page: int) -> tuple[str, list]:
        entries = list(reversed(self._load_reg()))          # newest first
        head = "📁 Saved repositories\n━━━━━━━━━━━━━━━━━\n"
        how = "To save one, paste its GitHub link here as a message."
        if not entries:
            return head + "Nothing saved yet.\n\n" + how, []
        name = self.ctx.name
        pages = max(1, -(-len(entries) // _PAGE))
        page = min(max(page, 0), pages - 1)
        rows = [[{"text": _clip(f"📁 {e['owner']}/{e['repo']}", 56),
                  "callback_data": f"{name}:s:{_repo_key(e['owner'], e['repo'])}:{page}"}]
                for e in entries[page * _PAGE:(page + 1) * _PAGE]]
        nav = []
        if page > 0:
            nav.append({"text": "◀ Newer", "callback_data": f"{name}:h:{page - 1}"})
        if page < pages - 1:
            nav.append({"text": "Older ▶", "callback_data": f"{name}:h:{page + 1}"})
        if nav:
            rows.append(nav)
        rows.append([{"text": "📤 Export the list", "callback_data": f"{name}:x"}])
        where = f"\nPage {page + 1} of {pages}" if pages > 1 else ""
        return (head + f"{len(entries)} saved. Tap one to open it.{where}\n\n" + how, rows)

    def _repo_screen(self, e: dict, page: int,
                     confirm_delete: bool = False) -> tuple[str, list]:
        name, key = self.ctx.name, _repo_key(e["owner"], e["repo"])
        if confirm_delete:
            return (f"🗑 Delete {e['owner']}/{e['repo']}?\n"
                    "The copy on this machine is removed too.", [[
                        {"text": "🗑 Yes, delete", "callback_data": f"{name}:D:{key}:{page}"},
                        {"text": "✖ No, keep it", "callback_data": f"{name}:s:{key}:{page}"},
                    ]])
        return self._details(e), [
            [{"text": "🌐 Open on GitHub",
              "url": f"https://github.com/{e['owner']}/{e['repo']}"}],
            [{"text": "📦 Send the bundle", "callback_data": f"{name}:b:{key}"}],
            [{"text": "🗑 Delete", "callback_data": f"{name}:d:{key}:{page}"},
             {"text": "⬅ Back", "callback_data": f"{name}:h:{page}"}],
        ]

    def on_callback(self, data: str, chat_id: int, message_id: int,
                    callback_id: str) -> None:
        # <plugin>:h:<page> | x | <s|d|D>:<key>:<page> | b:<key>
        # <plugin>:c:<key> (clone the pasted link) | n (don't)
        parts = data.split(":")
        verb, args = (parts[1] if len(parts) > 1 else ""), parts[2:]
        key = args[0] if args else ""
        answer = getattr(self.notifier, "answer_callback", None)

        def ack(text: str = "") -> None:
            if answer:
                answer(callback_id, text)

        def show(screen: tuple[str, list]) -> None:
            self._show(chat_id, message_id, *screen)

        if verb == "x":
            ack("Exporting…")
            self._cmd_export(chat_id, "")
            return
        if verb == "n":
            ack()
            self._show(chat_id, message_id, "✖ Not saved.", [])
            return
        if verb == "c":
            offered = self._offered.pop(key, None)
            if offered is None:
                ack("That offer has expired — paste the link again")
                return
            ack("Cloning…")
            self._show(chat_id, message_id, f"📁 Saving {offered[0]}/{offered[1]}…", [])
            self._cmd_clone(chat_id, *offered)
            return
        if verb not in ("s", "b", "d", "D"):
            ack()
            show(self._home_screen(_int(key)))
            return

        page = _int(args[1]) if len(args) > 1 else 0
        e = next((x for x in self._load_reg()
                  if _repo_key(x["owner"], x["repo"]) == key), None)
        if e is None:
            ack("That repository is no longer saved")
            show(self._home_screen(page))
        elif verb == "b":
            ack("Building the bundle…")
            self._send_bundle(chat_id, e)
        elif verb == "D":
            result = self._delete(e)
            ack("Deleted" if result.startswith("🗑") else "Could not delete")
            if not result.startswith("🗑") or "⚠️" in result:
                self._send(chat_id, result)
            show(self._home_screen(page))
        else:
            ack()
            show(self._repo_screen(e, page, confirm_delete=(verb == "d")))

    def _on_text(self, payload: dict) -> None:
        """A message that is nothing but a GitHub repo link: offer to save it."""
        chat_id = payload.get("chat_id")
        parsed = _parse_pasted(str(payload.get("text") or ""))
        if not chat_id or not parsed:
            return
        owner, repo = parsed
        saved = next((e for e in self._load_reg()
                      if e["owner"].lower() == owner.lower()
                      and e["repo"].lower() == repo.lower()), None)
        if saved:
            self._show(chat_id, None, *self._repo_screen(saved, 0))
            return
        name, key = self.ctx.name, _repo_key(owner, repo)
        if len(self._offered) >= 50:                # stale offers nobody tapped
            self._offered.clear()
        self._offered[key] = (owner, repo)
        self._send(chat_id, f"📁 Save {owner}/{repo}?\n"
                            "It is downloaded to this machine so you can get a bundle.",
                   buttons=[[{"text": "✅ Yes, save it", "callback_data": f"{name}:c:{key}"},
                             {"text": "✖ No", "callback_data": f"{name}:n"}]])

    def _show(self, chat_id: int, message_id: int | None, text: str,
              buttons: list) -> None:
        edit = getattr(self.notifier, "edit_message", None)
        if message_id is not None and edit:
            edit(chat_id, message_id, _clip(text, 3900), buttons=buttons)
        else:
            self._send(chat_id, text, buttons=buttons or None)

    # ─── helpers ────────────────────────────────────────────────

    def _send_help(self, chat_id: int) -> None:
        self._send(chat_id,
            "📁 /gh usage:\n"
            "  /gh                  Saved repositories, as buttons\n"
            "  /gh <owner/repo>     Clone shallow\n"
            "  /gh list [N]         Last N cloned\n"
            "  /gh show <name>      Metadata + README preview\n"
            "  /gh bundle <name>    Full .md bundle as document\n"
            "  /gh tag <name> a,b   Tag\n"
            "  /gh search <text>    Search\n"
            "  /gh delete <name>    Remove\n"
            "  /gh export           Library as .md")

    def _send(self, chat_id: int, text: str, buttons: list | None = None) -> None:
        """Send ``text`` (split if long); ``buttons`` go under the last part."""
        chunks = list(_chunk(text, 3900))
        for i, chunk in enumerate(chunks):
            extra = {"buttons": buttons} if buttons and i == len(chunks) - 1 else {}
            if hasattr(self.notifier, "send_to"):
                self.notifier.send_to(chat_id, chunk, **extra)
            else:
                self.notifier.send(chunk, **extra)


def _chunk(text: str, n: int):
    for i in range(0, len(text), n):
        yield text[i:i + n]
