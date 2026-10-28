import sys
import time

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


class FakeExecApi:
    """Yields demuxed (stdout, stderr) frames the way the SDK's stream does."""

    def __init__(self, frames=(), failure=None, stall=False):
        self.frames = frames
        self.failure = failure
        self.stall = stall
        self.seen_id = None

    def exec_start(self, exec_id, *, stream, demux):
        assert stream and demux
        self.seen_id = exec_id
        yield from self.frames
        if self.stall:
            time.sleep(5)
            yield b"late"
        if self.failure is not None:
            raise self.failure


def test_capture_exec_separates_demuxed_streams_and_leaves_the_exit_code_to_docker():
    api = FakeExecApi(frames=[(b"out\n", None), (None, b"err\n"), (b"more", b"both")])
    result, failure = capture_exec(
        api, "exec-1", ["caged", "command"], timeout_seconds=5, max_output_bytes=4096
    )
    assert api.seen_id == "exec-1"
    assert result.command == ["caged", "command"]
    assert result.stdout == "out\nmore"
    assert result.stderr == "err\nboth"
    assert result.exit_code is None  # Docker's exec record owns the exit code
    assert failure is None
    assert not result.timed_out and not result.output_truncated


def test_capture_exec_returns_a_broken_stream_and_keeps_its_partial_output():
    api = FakeExecApi(frames=[(b"partial", None)], failure=RuntimeError("connection reset"))
    result, failure = capture_exec(
        api, "exec-1", ["caged"], timeout_seconds=5, max_output_bytes=4096
    )
    assert result.stdout == "partial"
    assert isinstance(failure, RuntimeError)


def test_capture_exec_bounds_output_and_drains_to_the_end():
    api = FakeExecApi(frames=[(b"z" * 4096, None)] * 8)
    result, failure = capture_exec(
        api, "exec-1", ["caged"], timeout_seconds=5, max_output_bytes=1000
    )
    assert result.output_truncated
    assert not result.timed_out
    assert failure is None
    assert len(result.stdout.encode()) + len(result.stderr.encode()) <= 1000


def test_capture_exec_abandons_a_stalled_stream_after_its_deadline():
    api = FakeExecApi(stall=True)
    result, failure = capture_exec(
        api, "exec-1", ["caged"], timeout_seconds=0.05, max_output_bytes=4096
    )
    assert result.timed_out
    assert failure is None
    assert result.duration_seconds < 4
