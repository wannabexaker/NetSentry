"""github_explorer: cloning, the button list, bundles — and treating a cloned
repository as the untrusted content it is."""

from __future__ import annotations

import json
import logging
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from netsentry.core.events import EventBus
from netsentry.core.plugin import PluginContext
from netsentry.plugins.github_explorer import (
    GithubExplorerPlugin,
    _parse_pasted,
    _repo_key,
)

CHAT = 42
RUN = "netsentry.plugins.github_explorer.subprocess.run"


def _plugin(tmp_path: Path, **config) -> GithubExplorerPlugin:
    state = tmp_path / "state"
    state.mkdir(parents=True, exist_ok=True)
    ctx = PluginContext(
        name="github_explorer", config={"base_dir": str(tmp_path / "repos"), **config},
        router=Mock(), notifier=Mock(), vault=Mock(),
        logger=logging.getLogger("test.gh"), state_dir=str(state), events=EventBus(),
    )
    p = GithubExplorerPlugin(ctx)
    p.on_load()
    return p


def _fake_clone(files: dict[str, str] | None = None, returncode: int = 0):
    """A stand-in for ``git clone`` that writes ``files`` into the target folder."""
    calls: list[SimpleNamespace] = []

    def run(cmd, **kwargs):
        calls.append(SimpleNamespace(cmd=cmd, kwargs=kwargs))
        target = Path(cmd[-1])
        if returncode != 0:
            target.mkdir(parents=True, exist_ok=True)     # git can leave a stub behind
            return SimpleNamespace(returncode=returncode, stdout="",
                                   stderr="fatal: repository not found")
        for rel, body in (files or {"README.md": "# Demo\n\nHello.\n"}).items():
            path = target / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    run.calls = calls  # type: ignore[attr-defined]
    return run


def _clone(p: GithubExplorerPlugin, slug: str = "octo/demo",
           files: dict[str, str] | None = None) -> None:
    with patch(RUN, side_effect=_fake_clone(files)):
        p.on_command("/gh", slug, CHAT)


def _registry(tmp_path: Path) -> list[dict]:
    return json.loads((tmp_path / "state" / "repos.json").read_text(encoding="utf-8"))


def _sent(p: GithubExplorerPlugin) -> list[str]:
    return [c.args[1] for c in p.notifier.send_to.call_args_list]


def _buttons(call) -> list[dict]:
    return [b for row in (call.kwargs.get("buttons") or []) for b in row]


def _press(p: GithubExplorerPlugin, data: str) -> tuple[str, list[dict]]:
    p.notifier.edit_message.reset_mock()
    p.on_callback(data, CHAT, 7, "cb1")
    if not p.notifier.edit_message.called:
        return "", []
    call = p.notifier.edit_message.call_args
    return call.args[2], _buttons(call)


def _data(buttons: list[dict], label: str) -> str:
    return next(b["callback_data"] for b in buttons if label in b["text"])


# ─── recognising pasted links ────────────────────────────────────

@pytest.mark.parametrize("text, expected", [
    ("https://github.com/octo/demo", ("octo", "demo")),
    ("https://github.com/octo/demo/", ("octo", "demo")),
    ("https://github.com/octo/demo.git", ("octo", "demo")),
    ("https://www.github.com/octo/demo", ("octo", "demo")),
    ("  https://github.com/octo/demo/tree/main/src  ", ("octo", "demo")),
    ("https://github.com/octo/demo/blob/main/README.md#usage", ("octo", "demo")),
    ("https://github.com/octo/demo?tab=readme-ov-file", ("octo", "demo")),
    ("https://github.com/octo/my.dotted-name_1", ("octo", "my.dotted-name_1")),
])
def test_links_into_a_repository_are_recognised(text: str, expected: tuple) -> None:
    assert _parse_pasted(text) == expected


@pytest.mark.parametrize("text", [
    "", "octo/demo", "kitchen/cam", "see https://github.com/octo/demo",
    "https://github.com/octo/demo thanks", "https://github.com/octo",
    "https://github.com/settings/profile", "https://github.com/orgs/octo/people",
    "https://github.com/../etc", "https://github.com/octo/..", "https://github.com/-x/demo",
    "https://gist.github.com/octo/abc123", "https://github.com.evil.example/octo/demo",
    "https://evil.example/github.com/octo/demo", "ftp://github.com/octo/demo",
])
def test_everything_else_is_not_an_offer_to_clone(text: str) -> None:
    assert _parse_pasted(text) is None


# ─── cloning ─────────────────────────────────────────────────────

def test_clone_registers_the_repository(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    _clone(p, files={"README.md": "# Demo\n", "pyproject.toml": "[project]\n",
                     "src/a.py": "", "src/b.py": "", "web/app.ts": "",
                     "node_modules/dep/index.js": ""})
    (entry,) = _registry(tmp_path)
    assert (entry["owner"], entry["repo"]) == ("octo", "demo")
    assert Path(entry["path"]) == (tmp_path / "repos" / "octo" / "demo").resolve()
    summary = entry["context_summary"]
    assert summary["languages"][0] == ["Python", 2]
    assert "JavaScript" not in dict(summary["languages"])           # node_modules is skipped
    assert summary["manifests"] == ["pyproject.toml"] and summary["file_count"] == 5
    done = p.notifier.send_to.call_args_list[-1]
    assert "✅ Saved octo/demo — #1" in done.args[1] and "/gh bundle" not in done.args[1]
    assert "https://" not in done.args[1]                 # the link is a button
    assert any("bundle" in b["text"] for b in _buttons(done))


def test_clone_is_shallow_linkless_and_never_asks_for_a_password(tmp_path: Path) -> None:
    p = _plugin(tmp_path, clone_depth=7)
    run = _fake_clone()
    with patch(RUN, side_effect=run):
        p.on_command("/gh", "https://github.com/octo/demo.git", CHAT)
    call = run.calls[0]
    assert call.cmd[:4] == ["git", "-c", "core.symlinks=false", "clone"]
    assert "--depth=7" in call.cmd and call.cmd[-3:-1] == ["--", "https://github.com/octo/demo.git"]
    assert call.kwargs["env"]["GIT_TERMINAL_PROMPT"] == "0"
    assert call.kwargs["timeout"] == 180


def test_failed_clone_leaves_nothing_behind(tmp_path: Path) -> None:
    """Regression: a stub folder left by a failed clone made the next attempt
    say "Already cloned" and register an empty repository."""
    p = _plugin(tmp_path)
    with patch(RUN, side_effect=_fake_clone(returncode=128)):
        p.on_command("/gh", "octo/missing", CHAT)
    assert "Clone failed" in _sent(p)[-1] and "doesn't exist" in _sent(p)[-1]
    assert "fatal" not in _sent(p)[-1]                    # git's own words stay in the log
    assert not (tmp_path / "repos" / "octo" / "missing").exists()
    assert _registry(tmp_path) == []


def test_timed_out_clone_is_cleaned_up(tmp_path: Path) -> None:
    p = _plugin(tmp_path)

    def run(cmd, **kwargs):
        Path(cmd[-1]).mkdir(parents=True)
        (Path(cmd[-1]) / "half").write_text("x", encoding="utf-8")
        raise subprocess.TimeoutExpired(cmd, 180)

    with patch(RUN, side_effect=run):
        p.on_command("/gh", "octo/huge", CHAT)
    assert "timed out" in _sent(p)[-1]
    assert not (tmp_path / "repos" / "octo" / "huge").exists() and _registry(tmp_path) == []


def test_missing_git_is_explained_not_crashed(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    with patch(RUN, side_effect=FileNotFoundError("git")):
        p.on_command("/gh", "octo/demo", CHAT)
    assert "Could not run git" in _sent(p)[-1] and _registry(tmp_path) == []


def test_cloning_again_updates_instead_of_duplicating(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    _clone(p)
    with patch(RUN) as run:
        p.on_command("/gh", "Octo/Demo", CHAT)            # GitHub names ignore case
    run.assert_not_called()
    assert len(_registry(tmp_path)) == 1
    assert not (tmp_path / "repos" / "Octo").exists() or os.name == "nt"
    assert any("Already cloned" in t for t in _sent(p))


def test_not_a_repository_name(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    with patch(RUN) as run:
        for bad in ("nonsense", "a/b/c", "../etc", "octo/..", "https://example.org/octo/demo"):
            p.on_command("/gh", bad, CHAT)
            assert "Not a recognisable repo" in _sent(p)[-1], bad
    run.assert_not_called()


# ─── a repository is untrusted content ───────────────────────────

def _symlink(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("this machine does not allow creating symlinks")


def test_a_symlinked_readme_is_not_followed(tmp_path: Path) -> None:
    """A repo can ship README.md → /some/private/file. Following it would put
    that file into a bundle the owner then pastes into another tool."""
    p = _plugin(tmp_path)
    _clone(p, files={"src/a.py": ""})
    secret = tmp_path / "vault.key"
    secret.write_text("TOP-SECRET-KEY", encoding="utf-8")
    root = tmp_path / "repos" / "octo" / "demo"
    _symlink(root / "README.md", secret)
    _symlink(root / "Makefile", secret)
    ctx = p._scan_repo(root)
    assert ctx["readme"] == ""
    assert p._inline_extras(root, ctx["manifests"]) == []
    bundle = p._build_bundle_md(_registry(tmp_path)[0], root, ctx)
    assert "TOP-SECRET-KEY" not in bundle and "no README found" in bundle


def test_only_regular_files_inside_the_clone_are_read(tmp_path: Path) -> None:
    root = tmp_path / "clone"
    (root / "docs").mkdir(parents=True)
    (root / "README.md").write_text("hello " * 10, encoding="utf-8")
    read = GithubExplorerPlugin._read_repo_file
    assert read(root, "README.md", 1000) == "hello " * 10
    assert read(root, "README.md", 11) == "hello hello\n… [truncated]"
    assert read(root, "docs", 1000) is None               # a folder
    assert read(root, "nope.md", 1000) is None
    (tmp_path / "outside.txt").write_text("outside", encoding="utf-8")
    assert read(root, "../outside.txt", 1000) is None     # never climbs out


def test_delete_never_touches_a_folder_outside_the_repos_folder(tmp_path: Path) -> None:
    """The list is only a JSON file; a wrong path in it must not aim a delete
    at some other folder."""
    p = _plugin(tmp_path)
    _clone(p)
    precious = tmp_path / "precious"
    precious.mkdir()
    (precious / "keep.txt").write_text("keep", encoding="utf-8")
    entries = _registry(tmp_path)
    entries[0]["path"] = str(precious)
    p._save_reg(entries)
    p.on_command("/gh", "delete demo", CHAT)
    assert (precious / "keep.txt").exists()
    assert "left alone" in _sent(p)[-1]
    assert _registry(tmp_path) == []                      # it does leave the list


def test_the_repos_folder_itself_is_never_a_clone(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    base = tmp_path / "repos"
    assert p._inside_base(base / "octo" / "demo") is True
    assert p._inside_base(base) is False
    assert p._inside_base(base / ".." / "precious") is False
    assert p._inside_base(tmp_path) is False


def test_delete_removes_the_clone_and_the_entry(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    _clone(p)
    _clone(p, "octo/other")
    p.on_command("/gh", "rm demo", CHAT)
    assert not (tmp_path / "repos" / "octo" / "demo").exists()
    assert (tmp_path / "repos" / "octo" / "other").exists()
    assert [e["repo"] for e in _registry(tmp_path)] == ["other"]
    p.on_command("/gh", "delete demo", CHAT)
    assert "Not found" in _sent(p)[-1]
    p.on_command("/gh", "delete", CHAT)
    assert "type /gh delete" in _sent(p)[-1]


# ─── bundles ─────────────────────────────────────────────────────

def test_bundle_carries_readme_manifests_and_file_tree(tmp_path: Path) -> None:
    p = _plugin(tmp_path, bundle_max_inline_file_chars=30, max_files_listed=2)
    _clone(p, files={"README.md": "# Demo\n\nWhat it does.\n",
                     "pyproject.toml": "[project]\nname = 'demo'\n" + "x = 1\n" * 20,
                     "src/a.py": "print(1)\n", "src/b.py": "", "src/c.py": ""})
    bodies: list[str] = []

    def send_document(chat, path, caption="", filename=None):
        bodies.append(Path(path).read_text(encoding="utf-8"))
        assert filename == "gh-octo-demo-bundle.md"
        return True

    p.notifier.send_document.side_effect = send_document
    _press(p, f"github_explorer:b:{_repo_key('octo', 'demo')}")
    (bundle,) = bodies
    assert "# octo/demo — NetSentry bundle" in bundle
    assert "- Python: 3" in bundle and "- `pyproject.toml`" in bundle
    assert "```toml\n[project]" in bundle and "… [truncated]" in bundle
    assert "What it does." in bundle
    assert "… [+3 more files]" in bundle                  # 5 files, 2 listed
    p.notifier.answer_callback.assert_called_with("cb1", "Building the bundle…")


def test_bundle_falls_back_to_messages_and_reports_a_missing_clone(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    _clone(p)
    p.notifier.send_document.return_value = False
    p.on_command("/gh", "bundle 1", CHAT)
    assert any("NetSentry bundle" in t for t in _sent(p))
    import shutil
    shutil.rmtree(tmp_path / "repos" / "octo" / "demo")
    p.on_command("/gh", "bundle demo", CHAT)
    assert "Clone missing on disk" in _sent(p)[-1]
    p.on_command("/gh", "show demo", CHAT)
    assert "Clone missing on disk" in _sent(p)[-1]
    p.on_command("/gh", "bundle", CHAT)
    assert "type /gh bundle" in _sent(p)[-1]


# ─── the button list ─────────────────────────────────────────────

def test_bare_command_lists_repositories_as_buttons(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    p.on_command("/gh", "", CHAT)
    assert "Nothing saved yet" in _sent(p)[-1] and "paste its GitHub link" in _sent(p)[-1]
    for i in range(1, 9):
        _clone(p, f"octo/repo{i}")
    p.on_command("/gh", "", CHAT)
    home = p.notifier.send_to.call_args_list[-1]
    assert "8 saved" in home.args[1] and "Page 1 of 2" in home.args[1]
    labels = [b["text"] for b in _buttons(home) if ":s:" in b.get("callback_data", "")]
    assert labels[0] == "📁 octo/repo8" and len(labels) == 6            # newest first
    text, buttons = _press(p, _data(_buttons(home), "Older"))
    assert "Page 2 of 2" in text
    assert [b["text"] for b in buttons if ":s:" in b.get("callback_data", "")] == [
        "📁 octo/repo2", "📁 octo/repo1"]
    p.on_command("/gh", "help", CHAT)
    assert "what you can type" in _sent(p)[-1]


def test_open_then_delete_with_a_second_tap(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    _clone(p)
    key = _repo_key("octo", "demo")
    text, buttons = _press(p, f"github_explorer:s:{key}:0")
    assert "🐙 octo/demo" in text and "README preview:\nDemo" in text   # no literal #
    assert next(b for b in buttons if "Open on GitHub" in b["text"])["url"] == (
        "https://github.com/octo/demo")
    text, buttons = _press(p, _data(buttons, "Delete"))
    assert "Delete octo/demo?" in text and len(_registry(tmp_path)) == 1
    back, _ = _press(p, _data(buttons, "Cancel"))
    assert "README preview" in back and len(_registry(tmp_path)) == 1
    text, _ = _press(p, _data(buttons, "Yes, delete"))
    assert _registry(tmp_path) == [] and "Nothing saved yet" in text
    assert not (tmp_path / "repos" / "octo" / "demo").exists()


def test_buttons_fit_even_for_very_long_names(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    owner, repo = "o" * 39, "r" * 100                     # GitHub's own maximums
    _clone(p, f"{owner}/{repo}")
    entry = _registry(tmp_path)[0]
    for _text, rows in (p._home_screen(0), p._repo_screen(entry, 0),
                        p._repo_screen(entry, 0, confirm_delete=True)):
        for button in (b for row in rows for b in row):
            assert len(button.get("callback_data", "").encode()) <= 64
            assert len(button["text"]) <= 64


def test_a_button_for_a_repository_that_is_gone(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    _clone(p)
    text, _ = _press(p, "github_explorer:s:deadbeef:0")
    p.notifier.answer_callback.assert_called_with("cb1", "That repository is no longer saved")
    assert "1 saved" in text
    for data in ("github_explorer", "github_explorer:", "github_explorer:zz:1",
                 "github_explorer:h:notanumber"):
        text, _ = _press(p, data)
        assert "Saved repositories" in text, data


# ─── pasting a link ──────────────────────────────────────────────

def test_a_pasted_link_asks_first_then_clones(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    with patch(RUN) as run:
        p.ctx.events.publish("telegram.text",
                             {"chat_id": CHAT, "text": "https://github.com/octo/demo/tree/main"})
    run.assert_not_called()                               # nothing is downloaded unasked
    offer = p.notifier.send_to.call_args_list[-1]
    assert "Save octo/demo?" in offer.args[1]
    with patch(RUN, side_effect=_fake_clone()):
        _press(p, _data(_buttons(offer), "Yes"))
    assert [e["repo"] for e in _registry(tmp_path)] == ["demo"]
    # the same button a second time does nothing
    with patch(RUN) as run:
        _press(p, _data(_buttons(offer), "Yes"))
    run.assert_not_called()
    p.notifier.answer_callback.assert_called_with(
        "cb1", "That offer has expired — paste the link again")


def test_a_pasted_link_can_be_declined(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    p.ctx.events.publish("telegram.text", {"chat_id": CHAT, "text": "https://github.com/octo/demo"})
    offer = p.notifier.send_to.call_args_list[-1]
    with patch(RUN) as run:
        text, buttons = _press(p, _data(_buttons(offer), "No"))
    run.assert_not_called()
    assert text == "✖ Not saved." and buttons == [] and _registry(tmp_path) == []


def test_pasting_a_saved_repository_opens_it(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    _clone(p)
    p.notifier.reset_mock()
    p.ctx.events.publish("telegram.text", {"chat_id": CHAT, "text": "https://github.com/OCTO/demo"})
    shown = p.notifier.send_to.call_args_list[-1]
    assert "🐙 octo/demo" in shown.args[1] and "Save " not in shown.args[1]
    assert any("bundle" in b["text"] for b in _buttons(shown))


def test_ordinary_messages_are_not_offers(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    for text in ("kitchen/cam", "and/or", "https://github.com/settings/keys",
                 "see https://github.com/octo/demo"):
        p.ctx.events.publish("telegram.text", {"chat_id": CHAT, "text": text})
    p.ctx.events.publish("telegram.text", {"text": "https://github.com/octo/demo"})   # no chat
    assert _sent(p) == []
    quiet = _plugin(tmp_path / "quiet", offer_pasted_links=False)
    quiet.ctx.events.publish("telegram.text",
                             {"chat_id": CHAT, "text": "https://github.com/octo/demo"})
    assert _sent(quiet) == []


# ─── typed commands and the registry file ────────────────────────

def test_typed_list_tag_search_export(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    p.on_command("/gh", "list", CHAT)
    assert "No repos cloned yet" in _sent(p)[-1]
    p.on_command("/gh", "export", CHAT)
    assert "Nothing to export" in _sent(p)[-1]
    _clone(p, "octo/demo", {"main.go": ""})
    _clone(p, "octo/site", {"index.html": ""})
    p.on_command("/gh", "list 0", CHAT)                   # 0 used to mean "all of them"
    assert "last 1 of 2" in _sent(p)[-1]
    p.on_command("/gh", "tag demo Net Tools, Go", CHAT)
    assert _registry(tmp_path)[0]["tags"] == ["net_tools", "go"]
    p.on_command("/gh", "search net_tools", CHAT)
    assert "1 matches" in _sent(p)[-1] and "octo/demo" in _sent(p)[-1]
    p.on_command("/gh", "search html", CHAT)              # by language
    assert "octo/site" in _sent(p)[-1]
    p.on_command("/gh", "search zzz", CHAT)
    assert "No matches" in _sent(p)[-1]
    p.on_command("/gh", "tag nope x", CHAT)
    assert "Not found" in _sent(p)[-1]
    bodies: list[str] = []
    p.notifier.send_document.side_effect = (
        lambda chat, path, caption="", filename=None:
        bodies.append(Path(path).read_text(encoding="utf-8")) or True)
    _press(p, "github_explorer:x")
    assert "## 1. octo/demo `#net_tools` `#go`" in bodies[0] and "## 2. octo/site" in bodies[0]


def test_a_repository_is_found_by_name_number_or_full_name(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    _clone(p, "octo/demo")
    _clone(p, "other/demo")                               # same short name, two owners
    entries = p._load_reg()
    assert p._resolve(entries, "demo") is None            # ambiguous
    assert p._resolve(entries, "other/demo")["owner"] == "other"
    assert p._resolve(entries, "https://github.com/octo/demo")["owner"] == "octo"
    assert p._resolve(entries, "2")["owner"] == "other"
    assert p._resolve(entries, "9") is None


def test_a_damaged_registry_is_kept_not_overwritten(tmp_path: Path, caplog) -> None:
    p = _plugin(tmp_path)
    _clone(p)
    registry = tmp_path / "state" / "repos.json"
    registry.write_text(registry.read_text(encoding="utf-8")[:60], encoding="utf-8")
    with caplog.at_level(logging.ERROR):
        _clone(p, "octo/other")
    assert "damaged" in caplog.text
    assert "octo" in (tmp_path / "state" / "repos.json.corrupt").read_text(encoding="utf-8")
    assert [e["repo"] for e in _registry(tmp_path)] == ["other"]


def test_incomplete_registry_entries_are_ignored(tmp_path: Path) -> None:
    p = _plugin(tmp_path)
    (tmp_path / "state" / "repos.json").write_text(
        json.dumps([{"owner": "octo"}, "junk", {"owner": "octo", "repo": "ok",
                                                "path": str(tmp_path / "repos" / "octo" / "ok")}]),
        encoding="utf-8")
    assert [e["repo"] for e in p._load_reg()] == ["ok"]
    assert [r["repo"] for r in p.api_repos()] == ["ok"]
    p.on_command("/gh", "", CHAT)                         # does not crash on the junk rows
    assert "1 saved" in _sent(p)[-1]
