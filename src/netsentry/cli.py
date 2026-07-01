"""NetSentry command-line interface."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import click

from . import __version__
from .core.vault import Vault, VaultError
from .core.config import _default_config_path


@click.group()
@click.version_option(__version__)
def main():
    """NetSentry — modular home-network automation."""


# ─── init ──────────────────────────────────────────────────────────

@main.command()
@click.option("--force", is_flag=True, help="Overwrite existing vault (DANGEROUS)")
def init(force):
    """Create vault + config skeleton."""
    cfg_dir = Path(os.path.expanduser("~/.config/netsentry"))
    cfg_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    v = Vault()
    if v.exists() and not force:
        click.echo(f"Vault already exists at {v.key_path}")
        click.echo("Use --force to overwrite, or `netsentry secret …` to add keys.")
    else:
        if force and v.key_path.exists():
            v.key_path.unlink()
            if v.vault_path.exists():
                v.vault_path.unlink()
        v.init()
        click.secho(f"✓ Vault created: {v.key_path}", fg="green")

    cfg_path = _default_config_path()
    if cfg_path.exists():
        click.echo(f"Config already exists: {cfg_path}")
    else:
        # Find the bundled example
        example = Path(__file__).parent.parent.parent / "config.example.yaml"
        if example.exists():
            shutil.copy(example, cfg_path)
            click.secho(f"✓ Config skeleton: {cfg_path}", fg="green")
        else:
            click.secho("⚠ config.example.yaml not bundled — create manually", fg="yellow")

    click.echo()
    click.echo("Next steps:")
    click.echo("  netsentry secret set TELEGRAM_TOKEN …")
    click.echo("  netsentry secret set TELEGRAM_CHAT_ID …")
    click.echo("  netsentry secret set ROUTER_HOST 192.168.1.1")
    click.echo("  netsentry secret set ROUTER_USER netsentry")
    click.echo("  netsentry secret set SSH_KEY ~/.ssh/netsentry-router-key")
    click.echo("  netsentry secret set ALLOWED_CHAT_ID <same as chat id>")
    click.echo()
    click.echo(f"  edit {cfg_path}")
    click.echo("  netsentry start")


# ─── secret ────────────────────────────────────────────────────────

@main.group()
def secret():
    """Manage encrypted secrets."""


@secret.command("set")
@click.argument("key")
@click.argument("value")
def secret_set(key, value):
    v = Vault()
    v.set(key, value)
    click.secho(f"✓ Set {key} ({len(value)} chars)", fg="green")


@secret.command("get")
@click.argument("key")
def secret_get(key):
    v = Vault()
    val = v.get(key)
    if val is None:
        click.secho(f"Key not found: {key}", fg="red")
        sys.exit(1)
    click.echo(val)


@secret.command("list")
def secret_list():
    v = Vault()
    keys = v.list_keys()
    if not keys:
        click.echo("(empty)")
        return
    for k in keys:
        val = v.get(k) or ""
        masked = (val[:4] + "…" + val[-3:]) if len(val) > 8 else "*" * len(val)
        click.echo(f"  {k:<25} = {masked}")


@secret.command("delete")
@click.argument("key")
def secret_delete(key):
    v = Vault()
    if v.delete(key):
        click.secho(f"✓ Deleted {key}", fg="green")
    else:
        click.secho(f"Not found: {key}", fg="yellow")


@secret.command("rotate-key")
def secret_rotate_key():
    """Generate new master key, re-encrypt vault."""
    v = Vault()
    v.rotate_key()
    click.secho("✓ Key rotated. Restart NetSentry.", fg="green")


# ─── start ─────────────────────────────────────────────────────────

@main.command()
@click.option("--config", "-c", default=None, help="Override config path")
def start(config):
    """Start the NetSentry runtime (blocks). Use a systemd service in production."""
    from .core.runtime import Runtime
    try:
        rt = Runtime(config_path=config)
    except FileNotFoundError as e:
        click.secho(f"Config not found: {e}", fg="red")
        sys.exit(1)
    except VaultError as e:
        click.secho(str(e), fg="red")
        sys.exit(1)
    rt.start()


# ─── status ────────────────────────────────────────────────────────

@main.command()
def status():
    """Show NetSentry runtime status (queries systemd if available)."""
    import subprocess
    try:
        r = subprocess.run(["systemctl", "--user", "status", "netsentry"],
                           capture_output=True, text=True, timeout=5)
        click.echo(r.stdout or r.stderr)
    except FileNotFoundError:
        click.echo("systemctl not available")


# ─── config ────────────────────────────────────────────────────────

@main.command("config")
@click.option("--show", is_flag=True, help="Print resolved config (secrets masked)")
def config_cmd(show):
    """Inspect config."""
    cfg_path = _default_config_path()
    if not cfg_path.exists():
        click.secho(f"No config at {cfg_path}. Run `netsentry init`.", fg="red")
        sys.exit(1)
    if show:
        click.echo(cfg_path.read_text())
    else:
        click.echo(f"Config: {cfg_path}")
        click.echo("  Editable file. After changes restart NetSentry.")


if __name__ == "__main__":
    main()
