"""Reading CyberLab honeynet daily files.

The published format is **one JSON array per day**, laid out one attack session
per line. That shape defeats every off-the-shelf pandas reader, so this module
handles the unwrapping and streaming.

Nothing here ever yields the attacker-payload field: ``data`` can hold the
contents of an uploaded file, and this project never inspects it. The exclusion
is enforced here rather than left to the caller.
"""

from __future__ import annotations

import gzip
import json
import pathlib
from collections.abc import Iterator

__all__ = [
    "PAYLOAD_FIELD",
    "unwrap_line",
    "day_from_name",
    "iter_daily_files",
    "iter_events",
]

# Field that may contain attacker-uploaded file contents. Never yielded.
PAYLOAD_FIELD = "data"


def unwrap_line(line: str) -> str:
    """Strip JSON-array punctuation from one line of a CyberLab daily file.

    The whole file is a single JSON array, so an individual line is only a
    *fragment* of it and cannot be handed to ``json.loads`` directly:

    - the first line starts with ``[``
    - every line except the last ends with ``,``
    - the last line ends with ``]`` and has **no trailing newline**

    (That last point is why ``wc -l`` under-reports: it counts newlines, and
    this file does not end with one.)

    Returns ``''`` for a blank line.
    """
    s = line.strip()
    if s.startswith("["):      # only the first line
        s = s[1:]
    s = s.rstrip(",")           # every line except the last
    if s.endswith("]"):        # only the last line
        s = s[:-1]
    return s.strip()


def day_from_name(path) -> str:
    """Extract ``YYYY-MM-DD`` from ``cyberlab_YYYY-MM-DD.json.gz``."""
    stem = pathlib.Path(path).name.split(".")[0]
    return stem.rsplit("_", 1)[-1]


def iter_daily_files(raw_dir) -> list[pathlib.Path]:
    """Return daily ``.json.gz`` files in chronological order."""
    return sorted(pathlib.Path(raw_dir).glob("*.json.gz"))


def iter_events(path, drop_payload: bool = True, limit_sessions=None) -> Iterator[dict]:
    """Yield one flat event dict at a time from a CyberLab daily file.

    Streams: never holds more than a single line in memory, so the full ~10 GB
    dataset is processable in bounded RAM.

    Parameters
    ----------
    drop_payload:
        Drop the ``data`` field. It can contain attacker-uploaded file
        contents, which this project never inspects. (Safety rule.)
    limit_sessions:
        Stop after this many sessions (i.e. after this many lines).
    """
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        for n, line in enumerate(fh):
            if limit_sessions is not None and n >= limit_sessions:
                return
            body = unwrap_line(line)
            if not body:
                continue
            for events in json.loads(body).values():
                for ev in events:
                    if drop_payload:
                        ev.pop(PAYLOAD_FIELD, None)
                    yield ev