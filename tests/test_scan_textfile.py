"""`patched scan` with and without node_exporter's textfile directory.

The metrics file is optional; the scan record is not. The scanner is faked
(as tests/test_cli.py fakes it) and every path is under tmp_path.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from patched import cli, export, net
from patched.cli import main


def fake_scan(stages_ok: bool = True) -> dict:
    item = {"source": "brew-formula", "name": "jq", "version": "1.8.1", "in_use": True,
            "status": "clean", "advisories": []}
    return {"host": "host1", "stamp": "20261120T140000", "started": 100.0, "finished": 101.5,
            "items": [item], "errors": {} if stages_ok else {"npm": "npm not found"},
            "stages": {"brew": True, "apps": True, "uv": True, "npm": stages_ok, "listeners": True,
                       "launchd": True},
            "listeners": [], "launchd": [], "protections": {}, "macos": {"version": "27.0.1", "build": "26A434"}}


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The record's home under tmp_path; no PATCHED_TEXTFILE_DIR; the default is tmp_path/default."""
    h = tmp_path / "patched-home"
    monkeypatch.setattr(net, "HOME", h)
    monkeypatch.delenv("PATCHED_TEXTFILE_DIR", raising=False)
    monkeypatch.setattr(export, "DEFAULT_TEXTFILE_DIR", tmp_path / "default")
    monkeypatch.setattr(export, "TEXTFILE_DIR", tmp_path / "default")
    monkeypatch.setattr(cli.scanner, "run", lambda **kw: fake_scan())
    return h


def scan(*args: str):
    return CliRunner().invoke(main, ["scan", "-q", "--offline", "--no-update", *args])


def records(home: Path) -> list[Path]:
    return sorted((home / "scans").glob("*.json")) if (home / "scans").exists() else []


def written(d: Path) -> list[str]:
    """Every file in d, the dot ones too (a temp file left behind would show here)."""
    return sorted(p.name for p in d.iterdir()) if d.exists() else []


# --- rule 1: the directory exists: as before ---

@pytest.mark.parametrize("how", ["default", "env", "option"])
def test_an_existing_directory_gets_patched_prom_and_the_record(home: Path, tmp_path: Path,
                                                                 monkeypatch: pytest.MonkeyPatch, how: str) -> None:
    d = tmp_path / ("default" if how == "default" else "named")
    d.mkdir()
    if how == "env":
        monkeypatch.setenv("PATCHED_TEXTFILE_DIR", str(d))
    r = scan(*(["--textfile-dir", str(d)] if how == "option" else []))
    assert r.exit_code == 0, r.output
    assert written(d) == ["patched.prom"]
    assert "# TYPE patched_detail_series gauge" in (d / "patched.prom").read_text()
    [rec] = records(home)
    assert f"wrote {d / 'patched.prom'} (" in r.output and f"and {rec}" in r.output


# --- rule 2: nobody named one, and the default is missing ---

def test_a_missing_default_skips_patched_prom_and_keeps_the_record(home: Path, tmp_path: Path) -> None:
    default = tmp_path / "default"
    r = scan()
    assert r.exit_code == 0, r.output
    [rec] = records(home)
    assert r.output.splitlines()[-1] == (
        f"wrote {rec}; no patched.prom (no node_exporter textfile directory at {default}; "
        "set PATCHED_TEXTFILE_DIR to write one)")
    assert r.output.startswith("1 items: 0 exposed")  # the summary still prints
    assert not default.exists()  # never made, so nothing (not even a temp file) is left in it
    assert list(tmp_path.rglob("*patched.prom*")) == []


def test_a_missing_default_with_a_failed_stage_is_still_exit_1(home: Path, tmp_path: Path,
                                                               monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli.scanner, "run", lambda **kw: fake_scan(stages_ok=False))
    r = scan()
    assert r.exit_code == 1
    assert len(records(home)) == 1
    assert "no patched.prom (no node_exporter textfile directory" in r.output
    assert "FAILED stages: npm" in r.output


# --- rule 3: somebody named one, and it is missing ---

@pytest.mark.parametrize("how", ["env", "option"])
def test_a_named_missing_directory_is_one_line_exit_2(home: Path, tmp_path: Path,
                                                      monkeypatch: pytest.MonkeyPatch, how: str) -> None:
    (tmp_path / "default").mkdir()  # the default would do: a typo must still not fall back to it
    typo = tmp_path / "textfiel"
    if how == "env":
        monkeypatch.setenv("PATCHED_TEXTFILE_DIR", str(typo))
    ran = []
    monkeypatch.setattr(cli.scanner, "run", lambda **kw: ran.append(1) or fake_scan())
    r = scan(*(["--textfile-dir", str(typo)] if how == "option" else []))
    assert r.exit_code == 2
    assert len(r.output.strip().splitlines()) == 1 and str(typo) in r.output
    assert "Traceback" not in r.output
    assert ran == [] and records(home) == []  # refused before the scan
    assert not typo.exists() and written(tmp_path / "default") == []


# --- rule 4: -n writes nothing, so it never needs the directory ---

@pytest.mark.parametrize("case", ["exists", "default-missing", "named-missing"])
def test_dry_run_prints_the_prom_in_every_case(home: Path, tmp_path: Path,
                                              monkeypatch: pytest.MonkeyPatch, case: str) -> None:
    if case == "exists":
        (tmp_path / "default").mkdir()
    if case == "named-missing":
        monkeypatch.setenv("PATCHED_TEXTFILE_DIR", str(tmp_path / "nope"))
    r = scan("-n")
    assert r.exit_code == 0, r.output
    assert "# TYPE patched_detail_series gauge" in r.output
    assert records(home) == []
    assert list(tmp_path.rglob("*patched.prom*")) == []
