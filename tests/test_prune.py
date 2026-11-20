"""Old scan records go after each scan; the newest of each host always stays.

Every path is under tmp_path and `now` is fixed: no clock, no real records.
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest
from click.testing import CliRunner

from patched import cli, export, net
from patched.cli import main

NOW = time.mktime((2026, 11, 20, 15, 0, 0, 0, 0, -1))
DAY = 86400


def stamp(days_ago: float, now: float = NOW) -> str:
    return time.strftime("%Y%m%dT%H%M%S", time.localtime(now - days_ago * DAY))


def record(d: Path, host: str, days_ago: float, now: float = NOW) -> Path:
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{host}-{stamp(days_ago, now)}.json"
    p.write_text("{}")
    return p


def names(d: Path) -> list[str]:
    return sorted(p.name for p in d.iterdir())


# --- export.prune_records ---

def test_an_old_record_goes_and_a_new_one_stays(tmp_path: Path) -> None:
    old, new = record(tmp_path, "host1", 31), record(tmp_path, "host1", 29)
    assert export.prune_records(tmp_path, 30, NOW) == [old]
    assert names(tmp_path) == [new.name]


def test_zero_keeps_every_record(tmp_path: Path) -> None:
    record(tmp_path, "host1", 400), record(tmp_path, "host1", 0)
    assert export.prune_records(tmp_path, 0, NOW) == []
    assert len(names(tmp_path)) == 2


def test_only_old_records_the_newest_stays(tmp_path: Path) -> None:
    records = [record(tmp_path, "host1", d) for d in (90, 60, 45)]
    assert export.prune_records(tmp_path, 30, NOW) == records[:2]
    assert names(tmp_path) == [records[2].name]


def test_age_is_read_from_the_name_not_the_mtime(tmp_path: Path) -> None:
    import os
    old, new = record(tmp_path, "host1", 40), record(tmp_path, "host1", 1)
    os.utime(old, (NOW, NOW))  # touched today: still 40 days old by its name
    os.utime(new, (NOW - 400 * DAY,) * 2)
    assert export.prune_records(tmp_path, 30, NOW) == [old]


def test_a_file_that_is_not_a_record_stays(tmp_path: Path) -> None:
    keep = record(tmp_path, "host1", 1)
    others = ["notes.txt", "host1-20200101T000000.json.bak", "host1-2020-01-01.json", "-20200101T000000.json",
              "host1-20201399T000000.json", ".host1-20200101T000000.json.tmp"]
    for n in others:
        (tmp_path / n).write_text("x")
    (tmp_path / "host1-20200102T000000.json").mkdir()  # named like a record, but a directory
    assert export.prune_records(tmp_path, 30, NOW) == []
    assert names(tmp_path) == sorted([keep.name, "host1-20200102T000000.json", *others])


def test_a_host_name_with_a_dash_and_each_hosts_newest_stays(tmp_path: Path) -> None:
    a_old, a_new = record(tmp_path, "my-mac-mini", 50), record(tmp_path, "my-mac-mini", 40)
    b_old, b_new = record(tmp_path, "host1", 35), record(tmp_path, "host1", 2)
    assert export.record_time(a_old)[0] == "my-mac-mini"
    assert export.prune_records(tmp_path, 30, NOW) == [a_old, b_old]
    assert names(tmp_path) == sorted([a_new.name, b_new.name])


def test_a_missing_directory_prunes_nothing(tmp_path: Path) -> None:
    assert export.prune_records(tmp_path / "none", 30, NOW) == []


@pytest.mark.parametrize("raw,days", [(None, 30), ("", 30), ("7", 7), ("0", 0), (" 14 ", 14)])
def test_keep_days(raw: str | None, days: int) -> None:
    assert export.keep_days({} if raw is None else {"PATCHED_KEEP_DAYS": raw}) == days


@pytest.mark.parametrize("raw", ["-1", "1.5", "thirty", "²", "30d"])
def test_keep_days_refuses_what_is_not_a_whole_number(raw: str) -> None:
    with pytest.raises(ValueError, match="not a whole number of 0 or more"):
        export.keep_days({"PATCHED_KEEP_DAYS": raw})


# --- through `patched scan` ---

def fake_scan() -> dict:
    return {"host": "host1", "stamp": stamp(0, time.time()), "started": 100.0, "finished": 101.5,
            "items": [], "errors": {}, "listeners": [], "launchd": [], "protections": {}, "macos": {},
            "stages": {"brew": True, "apps": True, "uv": True, "npm": True, "osv": True,
                       "listeners": True, "launchd": True}}


@pytest.fixture
def scans(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A record home under tmp_path holding three records 40, 35 and 5 days old."""
    home = tmp_path / "home"
    monkeypatch.setattr(net, "HOME", home)
    textfile = tmp_path / "textfile"
    textfile.mkdir()
    monkeypatch.setenv("PATCHED_TEXTFILE_DIR", str(textfile))
    monkeypatch.delenv("PATCHED_KEEP_DAYS", raising=False)
    monkeypatch.setattr(cli.scanner, "run", lambda **kw: fake_scan())
    now = time.time()
    for d in (40, 35, 5):
        record(home / "scans", "host1", d, now)
    return home / "scans"


@pytest.mark.parametrize("quiet", [[], ["-q"]])
def test_scan_prunes_and_says_so_after_wrote(scans: Path, quiet: list[str]) -> None:
    r = CliRunner().invoke(main, ["scan", "--no-update", *quiet])
    assert r.exit_code == 0, r.output
    lines = r.stdout.splitlines()
    assert lines[-1] == "pruned 2 records older than 30 days"
    assert lines[-2].startswith("wrote ")
    assert len(names(scans)) == 2  # the 5-day one and the new one


def test_scan_with_nothing_to_prune_says_nothing(scans: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATCHED_KEEP_DAYS", "0")
    r = CliRunner().invoke(main, ["scan", "--no-update", "-q"])
    assert r.exit_code == 0 and "pruned" not in r.output
    assert len(names(scans)) == 4


def test_scan_with_a_bad_keep_days_says_so_and_prunes_nothing(scans: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATCHED_KEEP_DAYS", "a month")
    r = CliRunner().invoke(main, ["scan", "--no-update", "-q"])
    assert r.exit_code == 0, r.output  # the scan itself succeeds
    assert r.stderr == "PATCHED_KEEP_DAYS='a month' is not a whole number of 0 or more: no records pruned\n"
    assert "pruned " not in r.stdout and len(names(scans)) == 4


def test_scan_dry_run_prunes_nothing(scans: Path) -> None:
    before = names(scans)
    r = CliRunner().invoke(main, ["scan", "-n", "--no-update", "-q"])
    assert r.exit_code == 0 and "pruned" not in r.output
    assert names(scans) == before
