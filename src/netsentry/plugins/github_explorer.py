"""
github_explorer — Save GitHub repos and export browse-ready bundles.

No AI calls. The plugin does three things:

1. Shallow-clone a public repo under ~/.local/share/netsentry/repos/.
2. Track what you saved (list, tag, search, delete).
3. Pack the repo into one Markdown bundle (README + manifests + file tree)
   and ship it as a Telegram document so you can paste it into ChatGPT
   yourself.

Commands
--------
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

import json
import os
import re
import shutil
import subprocess
import tempfile
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from ..core.plugin import Plugin


_GH_URL_RE = re.compile(
    r"^https?://github\.com/"
    r"([\w.-]+)/([\w.-]+?)(?:\.git)?/?$"
)
_GH_SLUG_RE = re.compile(r"^([\w.-]+)/([\w.-]+)$")


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

    # ─── registry ───────────────────────────────────────────────

    def _load_reg(self) -> list[dict]:
        try:
            return json.loads(self._registry_path.read_text(encoding="utf-8"))
        except Exception:
            return []

    def _save_reg(self, entries: list[dict]) -> None:
        self._registry_path.write_text(
            json.dumps(entries, indent=2, ensure_ascii=False), encoding="utf-8"
        )

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

    # ─── dispatch ───────────────────────────────────────────────

    def on_command(self, command: str, args: str, chat_id: int) -> None:
        if command != "/gh":
            return
        args = args.strip()
        if not args:
            self._send_help(chat_id)
            return

        kw, _, rest = args.partition(" ")
        kw_l = kw.lower()
        rest = rest.strip()

        handlers = {
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
        target = self._base_dir / owner / repo
        entries = self._load_reg()
        existing = next((e for e in entries
                         if e["owner"] == owner and e["repo"] == repo), None)

        if not target.exists():
            self._send(chat_id, f"📁 Cloning {owner}/{repo}…")
            target.parent.mkdir(parents=True, exist_ok=True)
            url = f"https://github.com/{owner}/{repo}.git"
            try:
                r = subprocess.run(
                    ["git", "clone", f"--depth={self._clone_depth}",
                     "--no-tags", "--", url, str(target)],
                    capture_output=True, text=True, timeout=180,
                )
            except subprocess.TimeoutExpired:
                self._send(chat_id, "❌ Clone timed out.")
                return
            if r.returncode != 0:
                self._send(chat_id, f"❌ Clone failed:\n{r.stderr[-500:]}")
                return
        else:
            self._send(chat_id, "📁 Already cloned. Updating registry only.")

        ctx = self._scan_repo(target)
        entry = existing or {
            "owner": owner, "repo": repo, "path": str(target),
            "cloned_at": datetime.now().isoformat(timespec="seconds"),
            "tags": [],
        }
        entry["last_seen"] = datetime.now().isoformat(timespec="seconds")
        entry["context_summary"] = {
            "languages":  ctx["languages"],
            "manifests":  ctx["manifests"],
            "file_count": ctx["file_count"],
        }
        if not existing:
            entries.append(entry)
        self._save_reg(entries)

        idx = entries.index(entry) + 1
        langs = ", ".join(
            f"{language} ({count})" for language, count in ctx["languages"][:4]
        ) or "—"
        manifests = ", ".join(ctx["manifests"][:6]) or "—"
        self._send(chat_id,
            f"✅ {owner}/{repo}  →  #{idx}\n"
            f"📍 {target}\n"
            f"📊 {ctx['file_count']} files, langs: {langs}\n"
            f"📦 manifests: {manifests}\n\n"
            f"/gh bundle {repo}  to get the full Markdown bundle.")

    def _cmd_list(self, chat_id: int, rest: str) -> None:
        n = int(rest) if rest.isdigit() else 10
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
        target = Path(e["path"])
        ctx = self._scan_repo(target) if target.exists() else None
        if not ctx:
            self._send(chat_id, f"⚠️ Clone missing on disk: {target}")
            return

        readme_preview = (ctx["readme"] or "").strip().split("\n\n", 1)[0]
        if len(readme_preview) > 800:
            readme_preview = readme_preview[:800] + "…"
        tags = (" #" + " #".join(e.get("tags", []))) if e.get("tags") else ""
        langs = ", ".join(
            f"{language} ({count})" for language, count in ctx["languages"][:5]
        ) or "—"
        manifests = ", ".join(ctx["manifests"]) or "—"
        self._send(chat_id,
            f"📁 {e['owner']}/{e['repo']}{tags}\n"
            f"📍 {target}\n"
            f"📊 {ctx['file_count']} files\n"
            f"💻 {langs}\n"
            f"📦 {manifests}\n\n"
            f"README preview:\n{readme_preview or '(empty)'}\n\n"
            f"/gh bundle {e['repo']}  for the full export.")

    def _cmd_bundle(self, chat_id: int, rest: str) -> None:
        if not rest:
            self._send(chat_id, "Usage: /gh bundle <name|idx>")
            return
        entries = self._load_reg()
        e = self._resolve(entries, rest)
        if not e:
            self._send(chat_id, f"❌ Not found: {rest}")
            return
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
        entries = self._load_reg()
        e = self._resolve(entries, hint)
        if not e:
            self._send(chat_id, f"❌ Not found: {hint}")
            return
        tags = [t.strip().lower().replace(" ", "_") for t in raw_tags.split(",") if t.strip()]
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
        entries = self._load_reg()
        e = self._resolve(entries, rest)
        if not e:
            self._send(chat_id, f"❌ Not found: {rest}")
            return
        target = Path(e["path"])
        if target.exists():
            try:
                shutil.rmtree(target)
            except Exception as ex:
                self._send(chat_id, f"❌ rmtree failed: {ex}")
                return
        entries.remove(e)
        self._save_reg(entries)
        self._send(chat_id, f"🗑 Deleted {e['owner']}/{e['repo']}")

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
            p = root / name
            if p.exists() and p.is_file():
                try:
                    text = p.read_text(encoding="utf-8", errors="replace")
                    if len(text) > self._max_readme_chars:
                        text = text[: self._max_readme_chars] + "\n… [truncated]"
                    return text
                except Exception:
                    continue
        return ""

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
            p = root / name
            if not (p.exists() and p.is_file()):
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            if len(text) > self._bundle_max_inline_file_chars:
                text = text[: self._bundle_max_inline_file_chars] + "\n… [truncated]"
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

    # ─── helpers ────────────────────────────────────────────────

    def _send_help(self, chat_id: int) -> None:
        self._send(chat_id,
            "📁 /gh usage:\n"
            "  /gh <owner/repo>     Clone shallow\n"
            "  /gh list [N]         Last N cloned\n"
            "  /gh show <name>      Metadata + README preview\n"
            "  /gh bundle <name>    Full .md bundle as document\n"
            "  /gh tag <name> a,b   Tag\n"
            "  /gh search <text>    Search\n"
            "  /gh delete <name>    Remove\n"
            "  /gh export           Library as .md")

    def _send(self, chat_id: int, text: str) -> None:
        for chunk in _chunk(text, 3900):
            if hasattr(self.notifier, "send_to"):
                self.notifier.send_to(chat_id, chunk)
            else:
                self.notifier.send(chunk)


def _chunk(text: str, n: int):
    for i in range(0, len(text), n):
        yield text[i:i + n]
