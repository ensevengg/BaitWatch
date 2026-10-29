import contextlib
import os
import selectors
import socket
import struct
import subprocess
import time
from collections.abc import Callable, Sequence
from urllib.parse import urlsplit

from run.evidence import CommandResult

EXEC_GRACE_SECONDS = 3
_FRAME_HEADER = struct.Struct(">BxxxL")
_FRAME_STREAMS = {1: "stdout", 2: "stderr"}
_READ_CHUNK = 64 * 1024


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


def _read_chunk(stream):
    # docker-py hands back a SocketIO wrapper, a plain or TLS socket, or an
    # SSH channel depending on the transport; each exposes one of these.
    if hasattr(stream, "recv"):
        return stream.recv(_READ_CHUNK)
    if hasattr(stream, "read"):
        return stream.read(_READ_CHUNK)
    return os.read(stream.fileno(), _READ_CHUNK)


def _close_stream(stream):
    # The shutdown wakes a peer still blocked on the open side; closing both
    # layers covers docker-py's SocketIO wrapper and its underlying socket.
    raw = getattr(stream, "_sock", stream)
    with contextlib.suppress(AttributeError, OSError):
        raw.shutdown(socket.SHUT_RDWR)
    with contextlib.suppress(AttributeError, OSError):
        stream.close()
    if raw is not stream:
        with contextlib.suppress(AttributeError, OSError):
            raw.close()


def _deadline_timeout(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("exec transport deadline expired")
    return remaining


def _connect_exec_socket(api, deadline: float):
    adapter = api.get_adapter(api.base_url)
    path = getattr(adapter, "socket_path", None)
    if not isinstance(path, str):
        raise ValueError("exec capture requires a local Docker Unix socket")
    stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        stream.settimeout(_deadline_timeout(deadline))
        stream.connect(path)
        return stream
    except BaseException:
        _close_stream(stream)
        raise


def _start_exec(api, exec_id, deadline: float):
    path = urlsplit(api._url("/exec/{0}/start", exec_id)).path
    body = b'{"Tty":false,"Detach":false}'
    request = (
        f"POST {path} HTTP/1.1\r\nHost: localhost\r\n"
        "Connection: Upgrade\r\nUpgrade: tcp\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode("ascii") + body
    stream = _connect_exec_socket(api, deadline)
    try:
        stream.settimeout(_deadline_timeout(deadline))
        stream.sendall(request)
        header = bytearray()
        # Read no payload ahead of the framing parser; cap even a trickled header.
        while not header.endswith(b"\r\n\r\n"):
            if len(header) >= _READ_CHUNK:
                raise ValueError("exec HTTP response header exceeds the byte limit")
            stream.settimeout(_deadline_timeout(deadline))
            byte = stream.recv(1)
            if not byte:
                raise ConnectionError("exec start ended inside the HTTP response header")
            header.extend(byte)
        lines = bytes(header).split(b"\r\n")
        status = lines[0].split()
        if len(status) < 2 or status[0] not in (b"HTTP/1.0", b"HTTP/1.1"):
            raise ValueError("invalid exec HTTP response status")
        if status[1] not in (b"101", b"200"):
            raise ValueError(f"exec start HTTP status {status[1]!r}")
        if any(line.lower().startswith(b"transfer-encoding:") for line in lines[1:]):
            raise ValueError("unsupported exec HTTP transfer encoding")
        stream.setblocking(False)
        return stream
    except BaseException:
        _close_stream(stream)
        raise


def capture_exec(
    api,
    exec_id,
    command: Sequence[str],
    *,
    timeout_seconds: float,
    max_output_bytes: int,
) -> tuple[CommandResult, BaseException | None]:
    """Bounded capture read straight off the exec's raw socket.

    docker-py's streaming iterator hides socket errors as a clean end of
    stream and cannot be interrupted, so this reader owns the socket that
    the exec-start HTTP upgrade returns and parses Docker's multiplexed
    framing itself: an 8-byte header (stream type, padding, big-endian
    length) then exactly that many payload bytes. An EOF inside a header or
    payload, an unknown stream type or a socket error is returned as the
    failure; EOF on a frame boundary is a clean end whose exit code still
    belongs to Docker's exec record. Frames are consumed in fixed chunks —
    a header can declare up to 4 GiB, which is never allocated — and bytes
    past the shared output budget are read and discarded, so a flooding
    tool can neither stall the cage nor buffer output on the host.
    """
    started = time.monotonic()
    result = CommandResult(command=list(command))
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    remaining = max_output_bytes
    stopped_at: float | None = None
    failure: BaseException | None = None
    stream = None
    selector = selectors.DefaultSelector()
    try:
        hard_deadline = started + timeout_seconds + EXEC_GRACE_SECONDS
        try:
            stream = _start_exec(api, exec_id, hard_deadline)
        except Exception as exc:
            failure = exc
            if time.monotonic() - started >= timeout_seconds:
                result.timed_out = True
        if stream is not None and time.monotonic() - started >= timeout_seconds:
            result.timed_out = True
        elif stream is not None:
            selector.register(stream, selectors.EVENT_READ)
            pending = bytearray()
            frame_name = "stdout"
            frame_size = 0
            frame_left = 0
            while True:
                now = time.monotonic()
                if stopped_at is None and now - started >= timeout_seconds:
                    result.timed_out = True
                    stopped_at = started + timeout_seconds
                read_deadline = hard_deadline
                if stopped_at is not None:
                    read_deadline = min(read_deadline, stopped_at + EXEC_GRACE_SECONDS)
                if now >= read_deadline:
                    break
                if not selector.select(min(0.05, read_deadline - now)):
                    continue
                try:
                    chunk = _read_chunk(stream)
                except BlockingIOError:
                    continue
                except OSError as exc:
                    failure = exc
                    break
                if not chunk:
                    if frame_left:
                        failure = ValueError(
                            f"exec stream ended inside a frame payload "
                            f"({frame_size - frame_left} of {frame_size} bytes)"
                        )
                    elif pending:
                        failure = ValueError("exec stream ended inside a frame header")
                    break
                pending += chunk
                pos = 0
                while pos < len(pending):
                    if frame_left:
                        take = min(frame_left, len(pending) - pos)
                        part = pending[pos : pos + take]
                        pos += take
                        frame_left -= take
                        kept = part[:remaining]
                        captured[frame_name].extend(kept)
                        remaining -= len(kept)
                        if len(part) > len(kept):
                            result.output_truncated = True
                            if stopped_at is None:
                                # Keep draining so the cage cannot stall on a
                                # full pipe, but only for the grace period.
                                stopped_at = time.monotonic()
                    elif len(pending) - pos < _FRAME_HEADER.size:
                        break
                    else:
                        frame_type, frame_size = _FRAME_HEADER.unpack_from(pending, pos)
                        frame_name = _FRAME_STREAMS.get(frame_type, "")
                        if not frame_name:
                            failure = ValueError(
                                f"exec stream frame declares unknown stream type {frame_type}"
                            )
                            break
                        pos += _FRAME_HEADER.size
                        frame_left = frame_size
                if failure is not None:
                    break
                del pending[:pos]
    finally:
        selector.close()
        if stream is not None:
            _close_stream(stream)
    result.stdout = captured["stdout"].decode("utf-8", errors="replace")
    result.stderr = captured["stderr"].decode("utf-8", errors="replace")
    result.duration_seconds = time.monotonic() - started
    return result, failure
