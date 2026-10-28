import socket
import struct
import sys
import threading
import time
import tracemalloc

import pytest

from run.capture import capture_attached, capture_exec


def test_capture_separates_streams_and_does_not_execute_metadata():
    result = capture_attached(
        [sys.executable, "-c", "import sys; print('out'); print('err', file=sys.stderr)"],
        ["NEVER-EXECUTE-THIS-ON-HOST"],
        timeout_seconds=5,
        max_output_bytes=1024,
        stop_container=lambda: None,
    )
    assert result.stdout == "out\n"
    assert result.stderr == "err\n"
    assert result.exit_code == 0


def test_output_overflow_is_bounded_and_signals_stop():
    stopped = []
    result = capture_attached(
        [sys.executable, "-c", "print('x'*100000)"],
        ["container command"],
        timeout_seconds=5,
        max_output_bytes=1000,
        stop_container=lambda: stopped.append(True),
    )
    assert result.output_truncated
    assert len(result.stdout.encode()) + len(result.stderr.encode()) <= 1000
    assert stopped == [True]


def test_deadline_signals_stop():
    stopped = []
    result = capture_attached(
        [sys.executable, "-c", "import time; time.sleep(0.4)"],
        ["container command"],
        timeout_seconds=0.05,
        max_output_bytes=1000,
        stop_container=lambda: stopped.append(True),
    )
    assert result.timed_out
    assert stopped == [True]
    assert result.duration_seconds < 3


def test_overflow_after_deadline_still_marks_truncation():
    result = capture_attached(
        [sys.executable, "-c", "import time; time.sleep(0.4); print('x' * 100000)"],
        ["container command"],
        timeout_seconds=0.05,
        max_output_bytes=1000,
        stop_container=lambda: None,
    )
    assert result.timed_out
    assert result.output_truncated
    assert len(result.stdout.encode()) + len(result.stderr.encode()) <= 1000


def frame(stream_type: int, payload: bytes, *, declared: int | None = None) -> bytes:
    """One Docker multiplexed-stream frame: type, padding, big-endian length."""
    size = len(payload) if declared is None else declared
    return struct.pack(">BxxxL", stream_type, size) + payload


class FakeExecApi:
    """Hands capture_exec one end of a socketpair as the raw exec socket."""

    def __init__(self):
        self.timeout = 60
        self.peer, self.end = socket.socketpair()
        self.seen_id = None
        self.seen_timeout = None

    def exec_start(self, exec_id, *, socket):  # noqa: A002 - docker-py's keyword
        assert socket is True
        self.seen_id = exec_id
        self.seen_timeout = self.timeout
        return self.end

    def preload(self, data: bytes) -> None:
        self.peer.sendall(data)

    def finish(self) -> None:
        self.peer.close()


@pytest.fixture(autouse=True)
def fake_exec_start(monkeypatch):
    from run import capture

    start = capture._start_exec

    def dispatch(api, exec_id, deadline):
        if isinstance(api, FakeExecApi):
            return api.exec_start(exec_id, socket=True)
        return start(api, exec_id, deadline)

    monkeypatch.setattr(capture, "_start_exec", dispatch)


class ResettingSocket:
    """A readable exec socket whose first read fails like a reset connection."""

    def __init__(self, end):
        self._end = end

    def fileno(self):
        return self._end.fileno()

    def recv(self, size):
        raise ConnectionResetError("connection reset by peer")

    def shutdown(self, how):
        self._end.shutdown(how)

    def close(self):
        self._end.close()


def test_capture_exec_demuxes_frames_and_leaves_the_exit_code_to_docker():
    api = FakeExecApi()
    api.preload(frame(1, b"out\n") + frame(2, b"err\n") + frame(1, b"more"))
    api.finish()
    result, failure = capture_exec(
        api, "exec-1", ["caged", "command"], timeout_seconds=5, max_output_bytes=4096
    )
    assert api.seen_id == "exec-1"
    assert result.command == ["caged", "command"]
    assert result.stdout == "out\nmore"
    assert result.stderr == "err\n"
    assert result.exit_code is None  # Docker's exec record owns the exit code
    assert failure is None
    assert not result.timed_out and not result.output_truncated
    assert api.end.fileno() == -1  # the raw socket never outlives the call


def test_capture_exec_reports_eof_inside_a_frame_payload_and_keeps_partial_output():
    api = FakeExecApi()
    api.preload(frame(1, b"partial") + frame(1, b"abc", declared=12))
    api.finish()
    result, failure = capture_exec(
        api, "exec-1", ["caged"], timeout_seconds=5, max_output_bytes=4096
    )
    assert result.stdout == "partialabc"  # delivered bytes are kept, the cut is reported
    assert failure is not None
    assert "3 of 12 bytes" in str(failure)


def test_capture_exec_reports_eof_inside_a_frame_header():
    api = FakeExecApi()
    api.preload(frame(2, b"err") + b"\x01\x00\x00")
    api.finish()
    result, failure = capture_exec(
        api, "exec-1", ["caged"], timeout_seconds=5, max_output_bytes=4096
    )
    assert result.stderr == "err"
    assert failure is not None
    assert "frame header" in str(failure)


def test_capture_exec_reports_an_invalid_stream_type():
    api = FakeExecApi()
    api.preload(frame(7, b"boom"))
    api.finish()
    result, failure = capture_exec(
        api, "exec-1", ["caged"], timeout_seconds=5, max_output_bytes=4096
    )
    assert failure is not None
    assert "stream type 7" in str(failure)


def test_capture_exec_reports_a_socket_error_and_closes_the_stream():
    api = FakeExecApi()
    api.preload(b"x")  # readable, so the reader reaches the failing recv
    api.end = ResettingSocket(api.end)
    result, failure = capture_exec(
        api, "exec-1", ["caged"], timeout_seconds=5, max_output_bytes=4096
    )
    assert isinstance(failure, ConnectionResetError)
    assert api.end.fileno() == -1
    api.finish()


def test_capture_exec_flood_past_the_budget_stays_bounded_on_the_host():
    api = FakeExecApi()
    payload = b"z" * 65536

    def flood():
        try:
            for _ in range(1024):  # 64 MiB, the review's descheduled-consumer probe
                api.peer.sendall(frame(1, payload))
        except OSError:
            pass  # the reader may abandon the overflow after its grace period
        finally:
            api.peer.close()

    threads_before = threading.active_count()
    tracemalloc.start()
    try:
        writer = threading.Thread(target=flood)
        writer.start()
        result, failure = capture_exec(
            api, "exec-1", ["caged"], timeout_seconds=5, max_output_bytes=1024
        )
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
        writer.join(timeout=10)
    assert result.output_truncated
    assert not result.timed_out
    assert failure is None
    assert len(result.stdout.encode()) + len(result.stderr.encode()) <= 1024
    assert threading.active_count() == threads_before
    assert peak < 16 * 1024 * 1024  # the whole flood must never sit in host memory


def test_capture_exec_never_allocates_a_frame_by_its_declared_length():
    api = FakeExecApi()
    api.preload(frame(1, b"abc", declared=0xFFFFFFFF))
    api.finish()
    result, failure = capture_exec(
        api, "exec-1", ["caged"], timeout_seconds=5, max_output_bytes=1024
    )
    assert result.stdout == "abc"
    assert failure is not None
    assert "3 of 4294967295 bytes" in str(failure)


def test_capture_exec_abandons_a_stalled_socket_after_its_deadline():
    api = FakeExecApi()  # the peer stays open and silent
    threads_before = threading.active_count()
    result, failure = capture_exec(
        api, "exec-1", ["caged"], timeout_seconds=0.05, max_output_bytes=4096
    )
    assert result.timed_out
    assert failure is None
    assert 3 <= result.duration_seconds < 4
    assert threading.active_count() == threads_before  # no reader thread survives
    assert api.end.fileno() == -1
    assert api.peer.recv(1) == b""  # shut down, not left half-open
    api.finish()


def test_capture_exec_bounds_a_stalled_start_and_restores_the_client_timeout():
    class StalledStartApi(FakeExecApi):
        def exec_start(self, exec_id, *, socket):  # noqa: A002
            self.seen_id = exec_id
            self.seen_timeout = self.timeout
            time.sleep(0.15)  # past the caller's deadline, like a read timeout
            raise ConnectionError("exec start never answered")

    api = StalledStartApi()
    result, failure = capture_exec(
        api, "exec-1", ["caged"], timeout_seconds=0.05, max_output_bytes=4096
    )
    assert api.seen_timeout == 60  # capture does not mutate the shared client timeout
    assert api.timeout == 60  # restored for every other client call
    assert result.timed_out
    assert isinstance(failure, ConnectionError)


@pytest.mark.parametrize("start_delay", [None, 0.12])
def test_capture_exec_start_obeys_an_absolute_deadline(monkeypatch, start_delay):
    import docker

    peer, end = socket.socketpair()
    stop = threading.Event()
    response = b"HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n"

    monkeypatch.setattr("run.capture._connect_exec_socket", lambda *args: end)
    monkeypatch.setattr("run.capture.EXEC_GRACE_SECONDS", 0.3)

    def answer():
        try:
            peer.recv(4096)
            if start_delay is None:
                for byte in response:
                    peer.sendall(bytes([byte]))
                    if stop.wait(0.2):
                        break
            elif not stop.wait(start_delay):
                peer.sendall(response)
                stop.wait(1)
        except OSError:
            pass
        finally:
            peer.close()

    threads_before = threading.active_count()
    writer = threading.Thread(target=answer)
    api = docker.APIClient(base_url="unix:///unused.sock", version="1.45", timeout=60)
    writer.start()
    try:
        result, failure = capture_exec(
            api, "exec-1", ["caged"], timeout_seconds=0.05, max_output_bytes=4096
        )
    finally:
        stop.set()
        writer.join(timeout=1)
        api.close()
    assert result.timed_out
    assert result.duration_seconds < (0.43 if start_delay is None else 0.22)
    assert end.fileno() == -1
    assert api.timeout == 60
    assert threading.active_count() == threads_before
    if start_delay is None:
        assert isinstance(failure, TimeoutError)
    else:
        assert failure is None
