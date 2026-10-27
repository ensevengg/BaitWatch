import sys

from run.capture import capture_attached


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
