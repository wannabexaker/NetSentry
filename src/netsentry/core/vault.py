"""
Encrypted secrets vault. Wraps the Fernet key + ciphertext we already use,
but exposes it as a friendly API for plugins and core code.

Default locations (overridable):
    key:    ~/.config/netsentry/secrets.key   (mode 400)
    vault:  ~/.config/netsentry/secrets.enc   (mode 600)

API:
    v = Vault()
    v.get("TELEGRAM_TOKEN")
    v.set("TELEGRAM_TOKEN", "...")     # auto-encrypts & persists
    v.delete("FOO")
    v.list_keys()
    v.rotate_key()
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken


def _default_dir() -> Path:
    return Path(os.environ.get("NETSENTRY_CONFIG_DIR",
                               os.path.expanduser("~/.config/netsentry")))


class VaultError(RuntimeError):
    pass


class Vault:
    """Fernet-encrypted key/value store."""

    def __init__(self, key_path: Path | None = None, vault_path: Path | None = None):
        base = _default_dir()
        self.key_path = key_path or (base / "secrets.key")
        self.vault_path = vault_path or (base / "secrets.enc")
        self._cache: dict[str, str] | None = None

    # ─── public API ────────────────────────────────────────────────

    def init(self) -> None:
        """Create new key + empty vault (refuses if either exists)."""
        self.key_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.key_path.exists():
            raise VaultError(f"Key already exists at {self.key_path}")
        key = Fernet.generate_key()
        self.key_path.write_bytes(key)
        os.chmod(self.key_path, 0o400)
        # Empty vault
        enc = Fernet(key).encrypt(b"{}")
        self.vault_path.write_bytes(enc)
        os.chmod(self.vault_path, 0o600)

    def exists(self) -> bool:
        return self.key_path.exists() and self.vault_path.exists()

    def get(self, name: str, default: str | None = None) -> str | None:
        return self._load().get(name, default)

    def set(self, name: str, value: str) -> None:
        data = self._load()
        data[name] = value
        self._save(data)

    def delete(self, name: str) -> bool:
        data = self._load()
        if name not in data:
            return False
        del data[name]
        self._save(data)
        return True

    def list_keys(self) -> list[str]:
        return sorted(self._load().keys())

    def all(self) -> dict[str, str]:
        """Return a *copy* of all key→value pairs. Use carefully."""
        return dict(self._load())

    def rotate_key(self) -> None:
        """Generate new key and re-encrypt the vault."""
        data = self._load()
        new_key = Fernet.generate_key()
        self.key_path.write_bytes(new_key)
        os.chmod(self.key_path, 0o400)
        enc = Fernet(new_key).encrypt(json.dumps(data).encode())
        self.vault_path.write_bytes(enc)
        os.chmod(self.vault_path, 0o600)
        self._cache = None

    def import_dict(self, mapping: dict[str, str]) -> int:
        """Bulk insert. Returns number of keys touched."""
        data = self._load()
        data.update({k: str(v) for k, v in mapping.items()})
        self._save(data)
        return len(mapping)

    # ─── internals ─────────────────────────────────────────────────

    def _key(self) -> bytes:
        if not self.key_path.exists():
            raise VaultError(f"Key missing: {self.key_path}. Run `netsentry init`.")
        return self.key_path.read_bytes().strip()

    def _load(self) -> dict[str, str]:
        if self._cache is not None:
            return self._cache
        if not self.vault_path.exists():
            raise VaultError(f"Vault missing: {self.vault_path}")
        enc = self.vault_path.read_bytes()
        if not enc:
            self._cache = {}
            return self._cache
        try:
            self._cache = json.loads(Fernet(self._key()).decrypt(enc).decode())
        except InvalidToken as e:
            raise VaultError("Vault decryption failed — wrong key or corrupted vault") from e
        return self._cache

    def _save(self, data: dict[str, str]) -> None:
        enc = Fernet(self._key()).encrypt(json.dumps(data).encode())
        self.vault_path.write_bytes(enc)
        os.chmod(self.vault_path, 0o600)
        self._cache = data
