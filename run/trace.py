"""Bounded before/after snapshots of a staged tree; diffing shows what the cage changed."""

import errno
import hashlib
import json
import math
import os
import stat
import sys
import time
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

KINDS = frozenset({"file", "dir", "symlink", "other"})
_ENTRY_FIELDS = frozenset({"kind", "mode", "size", "sha256", "target", "error"})
_HEX_DIGITS = frozenset("0123456789abcdef")
_MAX_PATH_KEY = 65_536
_MAX_ERROR = 64
USAGE = "usage: trace.py snapshot ROOT [--limits JSON] | trace.py unlock ROOT [--limits JSON]"


class TraceError(RuntimeError):
    pass


@dataclass(frozen=True)
class TraceLimits:
    max_entries: int = 10_000
    max_bytes: int = 64 * 1024 * 1024
    max_file_bytes: int = 8 * 1024 * 1024
    max_depth: int = 64
    timeout_seconds: float = 15

    def __post_init__(self) -> None:
        counts = (self.max_entries, self.max_bytes, self.max_file_bytes)
        if any(type(value) is not int for value in counts) or any(value <= 0 for value in counts):
            raise ValueError("trace entry and byte limits must be positive integers")
        if type(self.max_depth) is not int or self.max_depth < 0:
            raise ValueError("trace depth limit must be a nonnegative integer")
        if (
            type(self.timeout_seconds) not in (int, float)
            or not is_finite(self.timeout_seconds)
            or self.timeout_seconds <= 0
        ):
            raise ValueError("trace timeout_seconds must be a finite positive int or float")


def is_finite(value: float) -> bool:
    # A huge int overflows float conversion and would never trip the deadline.
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


DEFAULT_LIMITS = TraceLimits()


@dataclass(frozen=True)
class Entry:
    # The recorded fields are the diff rule; dir sizes and mtimes are churn, never signals.
    kind: str
    mode: int
    size: int = 0
    sha256: str | None = None
    target: str | None = None
    error: str | None = None


def error_code(exc: OSError) -> str:
    # errno names are locale-independent and bounded, unlike strerror.
    return errno.errorcode.get(exc.errno, "OSError")


def snapshot(root: Path, limits: TraceLimits = DEFAULT_LIMITS) -> dict[str, Entry]:
    """fd-relative walk that never follows a symlink or opens a non-regular file.

    The staged tree is attacker-controlled after a cage run. Unreadable or
    racing entries get an error marker instead of silence, so a change in
    readability still diffs, and exceeding any limit fails closed.
    """
    if os.name != "posix":
        raise TraceError("filesystem tracing requires Linux/POSIX")
    root = Path(root).absolute()
    deadline = time.monotonic() + limits.timeout_seconds
    manifest: dict[str, Entry] = {}
    count = total = 0

    def check() -> None:
        if time.monotonic() > deadline:
            raise TraceError("snapshot timed out")

    def scan(dir_fd: int, name: str, rel: str, depth: int) -> None:
        nonlocal count, total
        check()
        if depth > limits.max_depth:
            raise TraceError("staged tree exceeds the nesting limit")
        count += 1
        if count > limits.max_entries:
            raise TraceError("staged tree exceeds the entry limit")
        try:
            metadata = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        except OSError as exc:
            # A vanished entry still owns its path; a readable file there later diffs.
            manifest[rel] = Entry(kind="other", mode=0, error=error_code(exc))
            return
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISLNK(metadata.st_mode):
            try:
                target = os.readlink(name, dir_fd=dir_fd)
            except OSError as exc:
                manifest[rel] = Entry(kind="symlink", mode=mode, error=error_code(exc))
            else:
                manifest[rel] = Entry(kind="symlink", mode=mode, target=target)
            return
        if stat.S_ISDIR(metadata.st_mode):
            try:
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)
            except OSError as exc:
                manifest[rel] = Entry(kind="dir", mode=mode, error=error_code(exc))
                return
            try:
                manifest[rel] = Entry(kind="dir", mode=mode)
                scan_dir(child, rel, depth + 1)
            except OSError as exc:
                manifest[rel] = Entry(kind="dir", mode=mode, error=error_code(exc))
            finally:
                os.close(child)
            return
        if stat.S_ISREG(metadata.st_mode):
            scan_file(dir_fd, name, rel, mode, metadata.st_size)
            return
        # FIFOs, sockets, and devices are recorded from metadata and never opened.
        manifest[rel] = Entry(kind="other", mode=mode, size=metadata.st_size)

    def scan_file(dir_fd: int, name: str, rel: str, mode: int, size: int) -> None:
        nonlocal total
        try:
            file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
        except OSError as exc:
            manifest[rel] = Entry(kind="file", mode=mode, size=size, error=error_code(exc))
            return
        try:
            opened = os.fstat(file_fd)
            if not stat.S_ISREG(opened.st_mode):
                # The name raced to a special file between lstat and open.
                manifest[rel] = Entry(kind="file", mode=mode, size=size, error="not-regular")
                return
            digest = hashlib.sha256()
            hashed = 0
            while chunk := os.read(file_fd, 64 * 1024):
                check()
                hashed += len(chunk)
                total += len(chunk)
                if hashed > limits.max_file_bytes or total > limits.max_bytes:
                    raise TraceError("staged tree exceeds the byte limit")
                digest.update(chunk)
            manifest[rel] = Entry(
                kind="file", mode=mode, size=opened.st_size, sha256=digest.hexdigest()
            )
        except OSError as exc:
            manifest[rel] = Entry(kind="file", mode=mode, size=size, error=error_code(exc))
        finally:
            os.close(file_fd)

    def scan_dir(dir_fd: int, rel: str, depth: int) -> None:
        with os.scandir(dir_fd) as entries:
            for entry in entries:
                child = f"{rel}/{entry.name}" if rel else entry.name
                scan(dir_fd, entry.name, child, depth)

    try:
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise TraceError(f"snapshot root is not a readable directory: {error_code(exc)}") from exc
    try:
        scan_dir(root_fd, "", 0)
    except OSError as exc:
        raise TraceError(f"snapshot root became unreadable: {error_code(exc)}") from exc
    finally:
        os.close(root_fd)
    return manifest


def unlock(root: Path, limits: TraceLimits = DEFAULT_LIMITS) -> int:
    """fd-relative walk that never follows symlinks; chmods only real directories
    to 0o777 so the host user can delete a tree the cage's uid locked.

    Returns the count of directories that stayed locked; raising fails closed.
    """
    if os.name != "posix":
        raise TraceError("staging unlock requires Linux/POSIX")
    root = Path(root).absolute()
    deadline = time.monotonic() + limits.timeout_seconds
    count = 0
    failures = 0

    def check() -> None:
        if time.monotonic() > deadline:
            raise TraceError("unlock timed out")

    def walk(dir_fd: int, depth: int) -> None:
        nonlocal count, failures
        check()
        if depth > limits.max_depth:
            raise TraceError("staged tree exceeds the nesting limit")
        with os.scandir(dir_fd) as entries:
            for entry in entries:
                check()
                count += 1
                if count > limits.max_entries:
                    raise TraceError("staged tree exceeds the entry limit")
                try:
                    metadata = os.stat(entry.name, dir_fd=dir_fd, follow_symlinks=False)
                except OSError:
                    continue  # a vanished entry cannot block removal
                if not stat.S_ISDIR(metadata.st_mode):
                    continue
                # chmod by name follows symlinks, but lstat proved this is a real
                # directory and the cage is dead; the O_NOFOLLOW open still
                # refuses anything swapped in underneath.
                if stat.S_IMODE(metadata.st_mode) != 0o777:
                    try:
                        os.chmod(entry.name, 0o777, dir_fd=dir_fd)
                    except OSError:
                        failures += 1
                        continue
                try:
                    child = os.open(
                        entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd
                    )
                except OSError:
                    failures += 1
                    continue
                try:
                    walk(child, depth + 1)
                finally:
                    os.close(child)

    try:
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise TraceError(f"unlock root is not a readable directory: {error_code(exc)}") from exc
    try:
        walk(root_fd, 0)
    finally:
        os.close(root_fd)
    return failures


def diff(before: dict[str, Entry], after: dict[str, Entry]) -> list[tuple[str, str]]:
    changes: list[tuple[str, str]] = []
    for path in before.keys() | after.keys():
        if path not in before:
            changes.append((path, "added"))
        elif path not in after:
            changes.append((path, "deleted"))
        elif before[path] != after[path]:
            changes.append((path, "modified"))
    changes.sort()
    return changes


def error_paths(manifest: dict[str, Entry]) -> list[str]:
    """Sorted paths whose snapshot entry carries an error marker."""
    return sorted(path for path, entry in manifest.items() if entry.error is not None)


def manifest_to_json(manifest: dict[str, Entry]) -> str:
    payload = {
        # None fields are omitted; surrogateescape names escape to pure-ASCII \udcXX.
        path: {key: value for key, value in asdict(entry).items() if value is not None}
        for path, entry in manifest.items()
    }
    return json.dumps(payload, sort_keys=True)


def manifest_from_json(text: str) -> dict[str, Entry]:
    """Strict validation: the text may be a helper container's tampered stdout."""
    try:
        payload = json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise TraceError(f"manifest is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise TraceError("manifest must be a JSON object")
    return {path: _entry_from_json(path, fields) for path, fields in payload.items()}


def _entry_from_json(path: str, fields: object) -> Entry:
    shown = repr(path)
    if (
        not isinstance(path, str)
        or not path
        or len(path) > _MAX_PATH_KEY
        or "\0" in path
        or any(part in ("", ".", "..") for part in path.split("/"))
    ):
        raise TraceError(f"manifest path key is not a bounded relative path: {shown}")
    if not isinstance(fields, dict) or not _ENTRY_FIELDS.issuperset(fields):
        raise TraceError(f"manifest entry {shown} has unknown or malformed fields")
    kind = fields.get("kind")
    if kind not in KINDS:
        raise TraceError(f"manifest entry {shown} has an unknown kind")
    mode = fields.get("mode")
    if type(mode) is not int or not 0 <= mode <= 0o7777:
        raise TraceError(f"manifest entry {shown} has invalid mode bits")
    size = fields.get("size", 0)
    if type(size) is not int or size < 0:
        raise TraceError(f"manifest entry {shown} has an invalid size")
    sha256 = fields.get("sha256")
    if sha256 is not None and not (
        isinstance(sha256, str) and len(sha256) == 64 and set(sha256) <= _HEX_DIGITS
    ):
        raise TraceError(f"manifest entry {shown} has an invalid sha256")
    target = fields.get("target")
    if target is not None and (not isinstance(target, str) or "\0" in target):
        raise TraceError(f"manifest entry {shown} has an invalid link target")
    error = fields.get("error")
    if error is not None and (
        not isinstance(error, str) or not error or len(error) > _MAX_ERROR or not error.isascii()
    ):
        raise TraceError(f"manifest entry {shown} has an invalid error marker")
    if kind == "file" and (sha256 is None) == (error is None):
        raise TraceError(f"manifest file entry {shown} needs exactly one of sha256 or error")
    if kind == "symlink" and (sha256 is not None or (target is None) == (error is None)):
        raise TraceError(f"manifest symlink entry {shown} needs exactly one of target or error")
    if kind in ("dir", "other") and (sha256 is not None or target is not None):
        raise TraceError(f"manifest {kind} entry {shown} must not carry a digest or target")
    if kind in ("dir", "symlink") and size != 0:
        raise TraceError(f"manifest {kind} entry {shown} must not carry a size")
    return Entry(kind=kind, mode=mode, size=size, sha256=sha256, target=target, error=error)


def main(argv: Sequence[str]) -> int:
    """Entry point for helper containers: snapshot ROOT | unlock ROOT."""
    if not (
        len(argv) == 2
        and argv[0] in {"snapshot", "unlock"}
        or len(argv) == 4
        and argv[0] in {"snapshot", "unlock"}
        and argv[2] == "--limits"
    ):
        print(USAGE, file=sys.stderr)
        return 2
    action, root = argv[0], Path(argv[1])
    try:
        limits = TraceLimits(**json.loads(argv[3])) if len(argv) == 4 else DEFAULT_LIMITS
        if action == "snapshot":
            print(manifest_to_json(snapshot(root, limits)))
            return 0
        failures = unlock(root, limits)
    except (TraceError, ValueError, TypeError) as exc:
        print(f"trace error: {exc}", file=sys.stderr)
        return 1
    if failures:
        print(f"trace error: {failures} directories stayed locked", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
