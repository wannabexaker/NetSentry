"""Small JSON state files that survive a crash and never fail silently.

Two rules, learned the hard way:

* **Write atomically.** A plain ``write_text`` that is interrupted (power cut,
  service restart) leaves half a file behind.
* **A file that cannot be read is not an empty file.** Treating it as empty
  means the next save overwrites whatever was there. A damaged file is moved
  aside as ``<name>.corrupt`` and reported, so it can still be recovered.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


def read_json(path: Path | str, default: Any) -> Any:
    """Return the parsed content of ``path``, or ``default`` when it is missing.

    When ``default`` is a list or a dict the content must be of the same type.
    Anything else on disk counts as damage: the file is kept as
    ``<name>.corrupt`` and ``default`` is returned.
    """
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return default
    try:
        data = json.loads(text)
        if isinstance(default, (list, dict)) and not isinstance(data, type(default)):
            raise ValueError(f"expected a {type(default).__name__}, "
                             f"found a {type(data).__name__}")
    except ValueError as e:
        aside = path.with_name(path.name + ".corrupt")
        try:
            os.replace(path, aside)
            log.error("%s is damaged (%s); kept as %s, starting empty",
                      path, e, aside.name)
        except OSError as move_error:
            log.error("%s is damaged (%s) and could not be moved aside: %s",
                      path, e, move_error)
        return default
    return data


def write_json(path: Path | str, data: Any) -> None:
    """Write ``data`` to ``path`` so a reader sees the old or the new file, never half."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)
