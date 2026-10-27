import os
import selectors
import subprocess
import time
from collections.abc import Callable, Sequence

from run.evidence import CommandResult


def capture_attached(
    attach_command: Sequence[str],
    container_command: Sequence[str],
    *,
    timeout_seconds: float,
    max_output_bytes: int,
    stop_container: Callable[[], None],
) -> CommandResult:
    """Only the Docker attach client runs on the host; `container_command` is recorded, not run."""
    started = time.monotonic()
    result = CommandResult(command=list(container_command))
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    remaining = max_output_bytes
    stopped_at: float | None = None
    process = subprocess.Popen(
        list(attach_command),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
    )
    selector = selectors.DefaultSelector()
    try:
        for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            assert stream is not None
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map():
            now = time.monotonic()
            if stopped_at is None and now - started >= timeout_seconds:
                result.timed_out = True
                stopped_at = now
                stop_container()
            if stopped_at is not None and now - stopped_at >= 3:
                process.kill()
                break
            for key, _ in selector.select(timeout=0.05):
                try:
                    chunk = os.read(key.fd, 64 * 1024)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                kept = chunk[:remaining]
                captured[key.data].extend(kept)
                remaining -= len(kept)
                if len(chunk) > len(kept):
                    result.output_truncated = True
                    if stopped_at is None:
                        stopped_at = time.monotonic()
                        stop_container()
        try:
            result.exit_code = process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            result.timed_out = True
            stop_container()
            process.kill()
            result.exit_code = process.wait(timeout=3)
    finally:
        selector.close()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=3)
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                stream.close()
    result.stdout = captured["stdout"].decode("utf-8", errors="replace")
    result.stderr = captured["stderr"].decode("utf-8", errors="replace")
    result.duration_seconds = time.monotonic() - started
    return result
