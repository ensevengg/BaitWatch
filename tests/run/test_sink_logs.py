import json
from pathlib import Path

import pytest

from run.evidence import NetworkHit
from run.sink_logs import SinkLog, read_sink_log


def write_log(path: Path, records) -> Path:
    with open(path, "w", encoding="utf-8") as file:
        for record in records:
            if isinstance(record, str):
                file.write(record + "\n")
            else:
                file.write(json.dumps(record, separators=(",", ":")) + "\n")
    return path


def dns_record(**overrides):
    record = {
        "kind": "dns",
        "ts": 1793000000.0,
        "source_ip": "10.13.37.20",
        "qname": "KR2GS3TUFY.evil.example",
        "qtype": "A",
        "decoded": [{"label": "KR2GS3TUFY", "encoding": "base32", "text": "fake-secret"}],
    }
    record.update(overrides)
    return record


def http_record(**overrides):
    record = {
        "kind": "http",
        "ts": 1793000000.0,
        "source_ip": "10.13.37.20",
        "method": "POST",
        "path": "/collect",
        "host": "exfil.evil.example",
        "headers": {"host": "exfil.evil.example"},
        "headers_truncated": False,
        "body": "bw_secret=fake",
        "body_truncated": False,
    }
    record.update(overrides)
    return record


def tls_record(**overrides):
    record = {
        "kind": "tls",
        "ts": 1793000000.0,
        "source_ip": "10.13.37.20",
        "sni": "exfil.evil.example",
    }
    record.update(overrides)
    return record


def ready(sink="dns"):
    return {"kind": "ready", "ts": 1793000000.0, "sink": sink}


def test_full_log_maps_every_kind(tmp_path):
    path = write_log(
        tmp_path / "sink.jsonl",
        [ready(), dns_record(), http_record(), tls_record(sni=None)],
    )
    log = read_sink_log(path)
    assert log.ready and not log.truncated and not log.problems
    assert log.dns_hits == [
        NetworkHit(
            source_ip="10.13.37.20",
            destination="KR2GS3TUFY.evil.example",
            detail="qtype=A decoded: base32(KR2GS3TUFY)=fake-secret",
        )
    ]
    assert log.http_hits[0].destination == "exfil.evil.example/collect"
    assert log.http_hits[0].detail == "POST body=bw_secret=fake"
    assert log.tls_hits == [
        NetworkHit(
            source_ip="10.13.37.20",
            destination="<no sni>",
            detail="ClientHello without SNI",
        )
    ]
    assert all(hit.scan_token is None for hit in log.dns_hits + log.http_hits + log.tls_hits)


def test_truncated_marker_sets_flag(tmp_path):
    path = write_log(tmp_path / "sink.jsonl", [ready("http"), {"kind": "log_truncated", "ts": 1.0}])
    log = read_sink_log(path)
    assert log.ready and log.truncated and not log.problems


def test_refused_contact_is_a_problem_not_a_hit(tmp_path):
    path = write_log(
        tmp_path / "sink.jsonl",
        [ready("http"), {"kind": "refused", "ts": 1.0, "source_ip": "10.13.37.20"}],
    )
    log = read_sink_log(path)
    assert log.ready and not log.truncated
    assert not log.http_hits
    assert len(log.problems) == 1
    assert "refused a connection" in log.problems[0] and "not captured" in log.problems[0]


def test_missing_ready_record(tmp_path):
    path = write_log(tmp_path / "sink.jsonl", [dns_record()])
    log = read_sink_log(path)
    assert not log.ready and not log.problems and len(log.dns_hits) == 1


def test_malformed_and_unknown_lines_are_problems_not_losses(tmp_path):
    path = write_log(
        tmp_path / "sink.jsonl",
        [
            ready(),
            "{not json",
            json.dumps([1, 2, 3]),
            {"kind": "future-record", "ts": 1.0},
            dns_record(),
        ],
    )
    log = read_sink_log(path)
    assert len(log.problems) == 3
    assert any("not JSON" in problem for problem in log.problems)
    assert any("not a JSON object" in problem for problem in log.problems)
    assert any("unknown kind 'future-record'" in problem for problem in log.problems)
    assert len(log.dns_hits) == 1


def test_records_with_bad_fields_become_problems(tmp_path):
    path = write_log(
        tmp_path / "sink.jsonl",
        [
            ready(),
            dns_record(source_ip=None),
            http_record(path=42),
            tls_record(sni=7),
            {"kind": "ready", "ts": 1.0, "sink": "mystery"},
        ],
    )
    log = read_sink_log(path)
    assert not log.dns_hits and not log.http_hits and not log.tls_hits
    assert len(log.problems) == 4
    assert all(problem.startswith("line ") for problem in log.problems)


def test_oversize_file_is_recorded_and_only_prefix_parsed(tmp_path):
    records = [ready()]
    records.extend(http_record(body="z" * 100) for _ in range(30))
    path = write_log(tmp_path / "sink.jsonl", records)
    log = read_sink_log(path, max_bytes=500)
    assert any("exceeds 500 bytes" in problem for problem in log.problems)
    assert len(log.http_hits) < 30
    assert log.ready


def test_missing_file_is_a_problem(tmp_path):
    log = read_sink_log(tmp_path / "absent.jsonl")
    assert not log.ready and not log.dns_hits
    assert any("cannot read" in problem for problem in log.problems)


def test_empty_file_has_no_hits(tmp_path):
    path = write_log(tmp_path / "sink.jsonl", [])
    log = read_sink_log(path)
    assert not log.ready and not log.truncated
    assert not log.dns_hits and not log.http_hits and not log.tls_hits and not log.problems


def test_http_detail_marks_truncation_and_missing_host(tmp_path):
    path = write_log(
        tmp_path / "sink.jsonl",
        [
            http_record(body="q" * 300, body_truncated=True, host=""),
            http_record(method="GET", body="", path="/probe"),
        ],
    )
    log = read_sink_log(path)
    assert log.http_hits[0].destination == "/collect"
    assert log.http_hits[0].detail.startswith("POST body=")
    assert log.http_hits[0].detail.endswith("body_truncated")
    assert len(log.http_hits[0].detail) <= 400
    assert log.http_hits[1].detail == "GET"


def test_unparseable_http_contact_maps_to_a_hit(tmp_path):
    path = write_log(
        tmp_path / "sink.jsonl",
        [
            ready("http"),
            http_record(method="", path="", host="", headers={}, body="", raw="\\x00\\x01binary"),
            http_record(method="", raw=42),
        ],
    )
    log = read_sink_log(path)
    assert log.http_hits[0].destination == "<unparsed>"
    assert log.http_hits[0].detail.startswith(" raw=\\x00\\x01binary")
    assert len(log.problems) == 1
    assert "raw is not a string" in log.problems[0]


def test_stopped_record_is_parsed(tmp_path):
    path = write_log(
        tmp_path / "sink.jsonl",
        [ready("dns"), {"kind": "stopped", "ts": 1.0, "sink": "dns"}],
    )
    log = read_sink_log(path)
    assert log.ready and log.stopped and not log.problems


def test_stopped_record_naming_no_known_sink_is_a_problem(tmp_path):
    path = write_log(
        tmp_path / "sink.jsonl",
        [ready("dns"), {"kind": "stopped", "ts": 1.0, "sink": "mystery"}],
    )
    log = read_sink_log(path)
    assert not log.stopped
    assert len(log.problems) == 1 and "stopped record names no known sink" in log.problems[0]


def test_record_after_the_stopped_marker_is_a_problem(tmp_path):
    path = write_log(
        tmp_path / "sink.jsonl",
        [ready("dns"), {"kind": "stopped", "ts": 1.0, "sink": "dns"}, dns_record()],
    )
    log = read_sink_log(path)
    assert log.stopped
    assert log.problems == ["line 3: record after the stopped marker"]
    assert not log.dns_hits


BAD_STRINGS = [None, 1, 1.5, True, [], {}, ["dns"], {"sink": "dns"}]
BAD_NUMBERS = ["now", None, True, [], {}]


@pytest.mark.parametrize(
    "record",
    [
        *[ready(sink=value) for value in BAD_STRINGS],
        *[{"kind": "ready", "ts": value, "sink": "dns"} for value in BAD_NUMBERS],
        *[{"kind": "stopped", "ts": 1.0, "sink": value} for value in BAD_STRINGS],
        *[{"kind": "stopped", "ts": value, "sink": "dns"} for value in BAD_NUMBERS],
        *[{"kind": "log_truncated", "ts": value} for value in BAD_NUMBERS],
        *[{"kind": "refused", "ts": 1.0, "source_ip": value} for value in BAD_STRINGS],
        *[{"kind": "refused", "ts": value, "source_ip": "10.13.37.20"} for value in BAD_NUMBERS],
        *[dns_record(source_ip=value) for value in BAD_STRINGS],
        *[dns_record(qname=value) for value in BAD_STRINGS],
        *[dns_record(qtype=value) for value in [None, 1.5, True, False, [], {}]],
        *[dns_record(ts=value) for value in BAD_NUMBERS],
        *[dns_record(decoded=value) for value in [None, 1, 1.5, True, "text", {}, {"a": 1}]],
        *[dns_record(decoded=[value]) for value in [None, 1, "text", [], {}]],
        *[dns_record(decoded=[{"text": value}]) for value in BAD_STRINGS],
        *[
            dns_record(decoded=[{"text": "ok", "label": value}])
            for value in [1, 1.5, True, None, [], {}]
        ],
        *[
            dns_record(decoded=[{"text": "ok", "encoding": value}])
            for value in [1, 1.5, True, None, [], {}]
        ],
        *[http_record(source_ip=value) for value in BAD_STRINGS],
        *[http_record(method=value) for value in BAD_STRINGS],
        *[http_record(path=value) for value in BAD_STRINGS],
        *[http_record(host=value) for value in BAD_STRINGS],
        *[http_record(body=value) for value in BAD_STRINGS],
        *[http_record(body_truncated=value) for value in [1, 0, "yes", None, [], {}]],
        *[http_record(raw=value) for value in [42, 1.5, True, [], {}]],
        *[
            http_record(headers=value)
            for value in [None, 1, "headers", [], [{"host": "x"}], {"host": 1}, {"host": None}]
        ],
        *[http_record(headers={"host": value}) for value in [1, 1.5, True, None, [], {}]],
        *[http_record(ts=value) for value in BAD_NUMBERS],
        *[tls_record(source_ip=value) for value in BAD_STRINGS],
        *[tls_record(sni=value) for value in [7, 1.5, True, [], {}]],
        *[tls_record(ts=value) for value in BAD_NUMBERS],
    ],
)
def test_wrong_typed_fields_become_line_problems_and_parsing_continues(tmp_path, record):
    path = write_log(tmp_path / "sink.jsonl", [record, dns_record()])
    log = read_sink_log(path)
    assert len(log.problems) == 1
    assert log.problems[0].startswith("line 1: ")
    assert not log.ready and not log.stopped and not log.truncated
    assert not log.http_hits and not log.tls_hits
    assert len(log.dns_hits) == 1


ARBITRARY_JSON = [
    None,
    True,
    False,
    0,
    -1,
    1.5,
    "",
    "text",
    [],
    [1, "x", None, {"a": []}],
    {},
    {"a": 1},
    {"kind": ["dns"]},
    {"kind": {"name": "dns"}},
    [[[[["deep"]]]]],
    {"nested": {"list": [1, {"x": None}]}},
]


def test_read_sink_log_never_raises_for_arbitrary_json_values(tmp_path):
    candidates = []
    for value in ARBITRARY_JSON:
        candidates.extend(
            [
                value,
                {"kind": value},
                ready(sink=value),
                {"kind": "stopped", "ts": value, "sink": value},
                {"kind": "log_truncated", "ts": value},
                {"kind": "refused", "ts": value, "source_ip": value},
                dns_record(source_ip=value),
                dns_record(qname=value),
                dns_record(qtype=value),
                dns_record(decoded=value),
                dns_record(decoded=[value]),
                dns_record(decoded=[{"text": value, "label": value, "encoding": value}]),
                dns_record(ts=value),
                http_record(source_ip=value),
                http_record(method=value),
                http_record(path=value),
                http_record(host=value),
                http_record(headers=value),
                http_record(body=value),
                http_record(body_truncated=value),
                http_record(raw=value),
                http_record(ts=value),
                tls_record(source_ip=value),
                tls_record(sni=value),
                tls_record(ts=value),
            ]
        )
    path = tmp_path / "sink.jsonl"
    for candidate in candidates:
        write_log(path, [candidate])
        assert isinstance(read_sink_log(path), SinkLog)


def test_read_sink_log_never_raises_for_hostile_json_lines(tmp_path):
    lines = [
        "[" * 10000 + "]" * 10000,
        '{"kind":"dns","ts":' + "9" * 5000 + "}",
        '{"kind":"ready","sink":"dns","ts":' + "9" * 5000 + "}",
        '{"kind":"dns","decoded":[{"text":"ok","label":' + "9" * 5000 + "}]}",
    ]
    path = tmp_path / "sink.jsonl"
    for line in lines:
        write_log(path, [line, dns_record()])
        log = read_sink_log(path)
        assert isinstance(log, SinkLog)
        assert log.problems and log.problems[0].startswith("line 1: ")
        assert len(log.dns_hits) == 1


def test_log_without_a_trailing_newline_is_a_problem(tmp_path):
    path = tmp_path / "sink.jsonl"
    path.write_text('{"kind":"ready","sink":"dns"}', encoding="utf-8")
    log = read_sink_log(path)
    assert log.ready
    assert log.problems == ["sink log ends with a partial line"]


def test_http_headers_truncated_is_surfaced_in_detail(tmp_path):
    path = write_log(
        tmp_path / "sink.jsonl", [http_record(headers_truncated=True, body="", raw="GET /x EXTRA")]
    )
    log = read_sink_log(path)
    assert not log.problems
    assert "headers_truncated" in log.http_hits[0].detail
    assert "raw=GET /x EXTRA" in log.http_hits[0].detail


def test_http_record_without_headers_truncated_is_a_problem(tmp_path):
    record = http_record()
    del record["headers_truncated"]
    path = write_log(tmp_path / "sink.jsonl", [record])
    log = read_sink_log(path)
    assert not log.http_hits
    assert len(log.problems) == 1
    assert "headers_truncated is not a boolean" in log.problems[0]


@pytest.mark.parametrize("value", [1, 0, "yes", None, [], {}])
def test_http_headers_truncated_wrong_type_is_a_problem(tmp_path, value):
    path = write_log(tmp_path / "sink.jsonl", [http_record(headers_truncated=value)])
    log = read_sink_log(path)
    assert not log.http_hits
    assert len(log.problems) == 1
    assert "headers_truncated is not a boolean" in log.problems[0]


def test_dns_unparsed_record_maps_to_a_hit_with_its_raw_preview(tmp_path):
    path = write_log(
        tmp_path / "sink.jsonl",
        [
            ready(),
            dns_record(qname="<unparsed>", qtype="unknown", decoded=[], raw="\\x00\\x01partial"),
        ],
    )
    log = read_sink_log(path)
    assert not log.problems
    assert log.dns_hits == [
        NetworkHit(
            source_ip="10.13.37.20",
            destination="<unparsed>",
            detail="qtype=unknown raw=\\x00\\x01partial",
        )
    ]


def test_dns_record_with_a_non_string_raw_is_a_problem(tmp_path):
    path = write_log(tmp_path / "sink.jsonl", [ready(), dns_record(raw=42)])
    log = read_sink_log(path)
    assert not log.dns_hits
    assert len(log.problems) == 1
    assert "raw is not a string" in log.problems[0]
