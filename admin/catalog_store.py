"""Atomic, locked load/save for the catalog files and manifest nginx serves
directly from static/ (bind-mounted read-only into the `static` container,
read-write here — see docker-compose.yml). No database: a `threading.Lock`
per file is enough at "one admin per pilot deployment" scale, the same
in-memory-is-enough call already made for verify's Store. Revisit only if a
real pilot's concurrency needs outgrow it.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
from pathlib import Path

from schema_types import KINDS

STATIC_DIR = Path(os.environ.get("STATIC_DIR", "static"))
CATALOG_DIR = STATIC_DIR / "catalog"
MANIFEST_PATH = STATIC_DIR / ".well-known" / "agent-embassy.json"

FILES: dict[str, Path] = {kind: CATALOG_DIR / f"{kind}.json" for kind in KINDS}

# Lazily created per-path, not pre-populated at import time — so tests can
# point FILES/MANIFEST_PATH at a tmp_path fixture and still get a working
# lock, without re-importing this module.
_locks: dict[Path, threading.Lock] = {}
_locks_meta_lock = threading.Lock()


class UnknownKind(ValueError):
    pass


def _lock_for(path: Path) -> threading.Lock:
    with _locks_meta_lock:
        if path not in _locks:
            _locks[path] = threading.Lock()
        return _locks[path]


def _read_json(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _atomic_write(path: Path, doc: dict) -> None:
    # Temp file MUST be written in the same directory as the target — only
    # then is os.replace() atomic (same filesystem). A tempfile.mkstemp() in
    # /tmp would silently lose that guarantee across a container's separate
    # volume mount.
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        # mkstemp() creates the temp file mode 0600 (owner-only) — confirmed
        # live to break nginx's read access after os.replace(), since the
        # `static` container's nginx worker runs as a different, non-root
        # user than `admin`'s. os.replace() does NOT inherit the original
        # file's permissions, so this has to be set explicitly, every write.
        os.chmod(tmp_path, 0o644)
        os.replace(tmp_path, path)
    except BaseException:
        os.unlink(tmp_path)
        raise


def _cleanup_stale_temp_files() -> None:
    """Removes leftover `.{name}.*.tmp` files from a previous run that never
    reached os.replace() -- confirmed live during adversarial review: a
    `docker kill` (or any SIGKILL/crash, e.g. an OOM) landing between
    mkstemp() and os.replace() in _atomic_write skips the `except
    BaseException: os.unlink(tmp_path)` cleanup entirely (a killed process
    runs no Python exception handlers), leaving a 0600 temp file sitting in
    static/catalog/ forever -- nothing else ever names or touches it again.
    Not a corruption risk (the target file itself is always left as either
    the old or the new complete content, since os.replace() is a single
    atomic rename), just disk litter, but worth sweeping since it costs
    nothing: no write can legitimately be in-flight before this module (and
    therefore the app importing it) has finished starting.
    """
    dirs = {path.parent for path in FILES.values()}
    dirs.add(MANIFEST_PATH.parent)
    for d in dirs:
        if not d.exists():
            continue
        for tmp in d.glob(".*.tmp"):
            try:
                tmp.unlink()
            except OSError:
                pass


_cleanup_stale_temp_files()


def _catalog_path(kind: str) -> Path:
    if kind not in FILES:
        raise UnknownKind(kind)
    return FILES[kind]


def list_items(kind: str) -> list[dict]:
    doc = _read_json(_catalog_path(kind))
    return doc.get("itemListElement", [])


def get_item(kind: str, index: int) -> dict:
    return list_items(kind)[index]


def add_item(kind: str, item: dict) -> None:
    path = _catalog_path(kind)
    with _lock_for(path):
        doc = _read_json(path)
        doc.setdefault("itemListElement", []).append(item)
        _atomic_write(path, doc)


def update_item(kind: str, index: int, item: dict) -> None:
    path = _catalog_path(kind)
    with _lock_for(path):
        doc = _read_json(path)
        items = doc.setdefault("itemListElement", [])
        items[index] = item  # raises IndexError on a stale/bad index — surfaced to the caller as 404
        _atomic_write(path, doc)


def delete_item(kind: str, index: int) -> None:
    path = _catalog_path(kind)
    with _lock_for(path):
        doc = _read_json(path)
        items = doc.setdefault("itemListElement", [])
        items.pop(index)
        _atomic_write(path, doc)


def load_manifest() -> dict:
    return _read_json(MANIFEST_PATH)


def update_manifest(mutate) -> dict:
    """Load -> mutate in place -> save the FULL document. `mutate` must only
    touch the keys it owns (see admin plan's round-trip-safety invariant) —
    this function guarantees the load-save cycle is atomic and locked, not
    that `mutate` behaves; that's on the caller (main.py's form handler)."""
    with _lock_for(MANIFEST_PATH):
        doc = _read_json(MANIFEST_PATH)
        mutate(doc)
        _atomic_write(MANIFEST_PATH, doc)
        return doc
