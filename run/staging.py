"""Copy a bounded repo without following symlinks or reading special files."""

import math
import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path


class StagingError(RuntimeError):
    pass


@dataclass(frozen=True)
class StagingLimits:
    max_entries: int = 10_000
    max_bytes: int = 64 * 1024 * 1024
    max_file_bytes: int = 8 * 1024 * 1024
    max_depth: int = 64
    timeout_seconds: float = 15
    exclude_names: tuple[str, ...] = (
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        ".ssh",
        ".aws",
        ".gnupg",
    )

    def __post_init__(self) -> None:
        if any(
            type(value) is not int
            for value in (self.max_entries, self.max_bytes, self.max_file_bytes, self.max_depth)
        ):
            raise ValueError("staging entry, byte, and depth limits must be integers")
        if type(self.timeout_seconds) not in (int, float) or not is_finite(self.timeout_seconds):
            raise ValueError("staging timeout_seconds must be a finite int or float")


def is_finite(value: float) -> bool:
    # A huge int overflows float conversion and would never trip the deadline.
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def stage_repository(source: Path, destination: Path, limits: StagingLimits) -> list[str]:
    """Linux fd-relative traversal; stripped modes apply only to the disposable copy.

    A changing source can make the copy fail, but cannot redirect an open through a
    symlink. This is a bounded staging operation, not an atomic repository snapshot.
    """
    if os.name != "posix":
        raise StagingError("repository staging requires Linux/POSIX")
    source = Path(source).absolute()
    destination = Path(destination).absolute()
    if source == destination or source in destination.parents:
        raise StagingError("staging destination must be outside the source repository")
    deadline = time.monotonic() + limits.timeout_seconds
    count = total = 0
    excluded: list[str] = []

    def check() -> None:
        if time.monotonic() > deadline:
            raise StagingError("repository staging timed out")

    def copy_directory(source_fd: int, target: Path, depth: int) -> None:
        nonlocal count, total
        check()
        if depth > limits.max_depth:
            raise StagingError("repository exceeds the nesting limit")
        target.mkdir(mode=0o777)
        # The cage's uid 65532 must be able to write this disposable copy so
        # changes can be traced; the 0700 scan directory keeps other host users out.
        target.chmod(0o777)
        with os.scandir(source_fd) as entries:
            for entry in entries:
                check()
                count += 1
                if count > limits.max_entries:
                    raise StagingError("repository exceeds the entry limit")
                secret_env = entry.name == ".env" or (
                    entry.name.startswith(".env.") and entry.name != ".env.example"
                )
                if entry.name in limits.exclude_names or secret_env:
                    if depth == 0 and entry.name == ".git":
                        metadata = os.stat(entry.name, dir_fd=source_fd, follow_symlinks=False)
                        if not stat.S_ISDIR(metadata.st_mode):
                            raise StagingError("top-level .git exclusion is not a directory")
                    excluded.append((target / entry.name).relative_to(destination).as_posix())
                    continue
                metadata = os.stat(entry.name, dir_fd=source_fd, follow_symlinks=False)
                output = target / entry.name
                if stat.S_ISLNK(metadata.st_mode):
                    os.symlink(os.readlink(entry.name, dir_fd=source_fd), output)
                elif stat.S_ISDIR(metadata.st_mode):
                    child = os.open(
                        entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=source_fd
                    )
                    try:
                        copy_directory(child, output, depth + 1)
                    finally:
                        os.close(child)
                elif stat.S_ISREG(metadata.st_mode):
                    file_fd = os.open(
                        entry.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=source_fd
                    )
                    try:
                        opened = os.fstat(file_fd)
                        if opened.st_nlink != 1:
                            raise StagingError("hard-linked files are not allowed in staging")
                        if not stat.S_ISREG(opened.st_mode):
                            raise StagingError("repository changed to a non-regular file")
                        copied = 0
                        with output.open("xb") as writer:
                            while chunk := os.read(file_fd, 64 * 1024):
                                check()
                                copied += len(chunk)
                                total += len(chunk)
                                if copied > limits.max_file_bytes or total > limits.max_bytes:
                                    raise StagingError("repository exceeds the byte limit")
                                writer.write(chunk)
                        # Setuid/setgid bits never carry into the writable copy.
                        output.chmod(0o777 if metadata.st_mode & 0o111 else 0o666)
                    finally:
                        os.close(file_fd)
                else:
                    raise StagingError("repository contains a device, socket, or FIFO")

    root_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        copy_directory(root_fd, destination, 0)
    finally:
        os.close(root_fd)

    return excluded
