# Contributing to NetSentry

Thanks for being here. This project is small on purpose: every plugin is a
single file, every abstraction has one obvious extension point.

## Ground rules

- One plugin = one file in `src/netsentry/plugins/`. If it doesn't fit,
  split it.
- No coupling to MikroTik in plugins. Talk to `self.router`. Routers other
  than MikroTik will be supported through new `Router` subclasses, and
  every plugin must keep working.
- No coupling to Telegram in plugins either. Talk to `self.notifier`.
  Same logic applies for future notifiers (Discord, email, Pushover).
- Secrets never live in source. They go in the encrypted vault and are
  referenced from `config.yaml` via `${vault:KEY}`.
- Logs through `self.log`. No `print()`.

## Local development

```bash
git clone https://github.com/wannabexaker/NetSentry.git
cd NetSentry
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"

netsentry init                # creates vault + config
netsentry start               # foreground; Ctrl-C to stop
```

## Tests

```bash
pytest                        # if you added unit tests
ruff check .                  # lint
```

There is no full test suite yet. Adding one is the most welcome
contribution we can think of.

## Pull requests

- Branch off `main`, name the branch descriptively
  (`plugin/parental-control`, `fix/scheduler-timezone`).
- One concern per PR. A new plugin is one PR. A bug fix is another.
- Commit messages: imperative, present tense, no AI co-author lines.
- Update `docs/CHANGELOG.md` under an `## [Unreleased]` heading.

## New plugin checklist

- [ ] File in `src/netsentry/plugins/<name>.py`
- [ ] `class <Name>Plugin(Plugin):` with `COMMANDS = [...]` if exposing a
      slash command
- [ ] Entry added to `config.example.yaml` with safe defaults
- [ ] One paragraph in `README.md` under Features (if user-visible)
- [ ] If it calls `self.ai`, gate every call behind `self.ai.is_available()`
      so the bot fails fast when the host is off.

## New router or notifier adapter

- Subclass `Router` (in `core/router.py`) or `Notifier` (in
  `core/notifier.py`).
- Add a builder branch in the corresponding `build_*` factory.
- Document the new `type:` value in `config.example.yaml`.
- Existing plugins should not require changes.

## Code style

Run `ruff check .` and `ruff format .` before sending the PR.
Python 3.11+. Type hints encouraged but not enforced.

## License

By contributing you agree your contributions ship under the same MIT
license as the rest of the project.
