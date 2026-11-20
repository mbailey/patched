"""Homebrew's prefix (Apple silicon, Intel, or $HOMEBREW_PREFIX) and macOS only.

The existence checks are faked: both prefixes point under tmp_path, so the
real /opt/homebrew and /usr/local are never read.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner
from conftest import FakeLaunchd

from patched import cli, export, mac, net, schedule
from patched.cli import main


@pytest.fixture
def prefixes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    """Two fake prefixes, neither with a brew yet; no HOMEBREW_PREFIX."""
    silicon, intel = tmp_path / "opt-homebrew", tmp_path / "usr-local"
    monkeypatch.setattr(mac, "APPLE_SILICON", silicon)
    monkeypatch.setattr(mac, "INTEL", intel)
    monkeypatch.delenv("HOMEBREW_PREFIX", raising=False)
    return {"silicon": silicon, "intel": intel}


def brew(prefix: Path) -> Path:
    (prefix / "bin").mkdir(parents=True, exist_ok=True)
    (prefix / "bin" / "brew").write_text("#!/bin/sh\n")
    return prefix


# --- the prefix, in order ---

def test_homebrew_prefix_set_wins_over_both(prefixes: dict, tmp_path: Path) -> None:
    brew(prefixes["silicon"]), brew(prefixes["intel"])
    assert mac.brew_prefix({"HOMEBREW_PREFIX": str(tmp_path / "custom")}) == tmp_path / "custom"


def test_apple_silicon_brew_first(prefixes: dict) -> None:
    brew(prefixes["silicon"]), brew(prefixes["intel"])
    assert mac.brew_prefix({}) == prefixes["silicon"]


def test_intel_brew_when_there_is_no_apple_silicon_one(prefixes: dict) -> None:
    brew(prefixes["intel"])
    assert mac.brew_prefix({}) == prefixes["intel"]


def test_no_brew_at_all_is_apple_silicons_prefix(prefixes: dict) -> None:
    assert mac.brew_prefix({}) == prefixes["silicon"]


def test_an_empty_homebrew_prefix_is_unset(prefixes: dict) -> None:
    brew(prefixes["intel"])
    assert mac.brew_prefix({"HOMEBREW_PREFIX": ""}) == prefixes["intel"]


def test_the_process_environment_is_the_default(prefixes: dict, monkeypatch: pytest.MonkeyPatch,
                                                tmp_path: Path) -> None:
    monkeypatch.setenv("HOMEBREW_PREFIX", str(tmp_path / "env"))
    assert mac.brew_prefix() == tmp_path / "env"


# --- what follows the prefix ---

def test_textfile_default_and_agent_path_follow_an_intel_prefix(prefixes: dict, tmp_path: Path) -> None:
    intel = brew(prefixes["intel"])
    assert export.default_textfile_dir({}) == intel / "var/lib/node_exporter/textfile_collector"
    floor = schedule.floor({"HOME": str(tmp_path / "home")})
    assert floor[:2] == [f"{tmp_path / 'home'}/.local/bin", f"{intel}/bin"]
    assert f"{prefixes['silicon']}/bin" not in floor


def test_on_apple_silicon_the_paths_are_as_before(prefixes: dict, tmp_path: Path) -> None:
    silicon = brew(prefixes["silicon"])
    assert export.default_textfile_dir({}) == silicon / "var/lib/node_exporter/textfile_collector"
    assert schedule.floor({"HOME": "/h"})[1] == f"{silicon}/bin"


# --- macOS only ---

@pytest.fixture
def linux(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> list:
    """This is Linux; any scan that starts is recorded; the record's home is under tmp_path."""
    monkeypatch.setattr(mac, "system", lambda: ("linux", "Linux"))
    monkeypatch.setattr(net, "HOME", tmp_path / "patched-home")
    monkeypatch.setenv("PATCHED_TEXTFILE_DIR", str(tmp_path / "textfile"))
    ran: list = []
    monkeypatch.setattr(cli.scanner, "run", lambda **kw: ran.append(kw) or {})
    return ran


LINE = "patched scans macOS only for now; this is Linux.\n"


@pytest.mark.parametrize("args", [["scan"], ["scan", "-n"], ["scan", "-q", "--offline", "--no-update"]])
def test_scan_off_macos_stops_before_any_work(linux: list, tmp_path: Path, args: list[str]) -> None:
    r = CliRunner().invoke(main, args)
    assert r.exit_code == 2 and r.output == LINE
    assert linux == []  # no stage ran
    assert not (tmp_path / "patched-home").exists() and not (tmp_path / "textfile").exists()


@pytest.mark.parametrize("args", [["on"], ["on", "-n"]])
def test_schedule_on_off_macos_stops_before_any_work(linux: list, fake_launchd: FakeLaunchd,
                                                     args: list[str]) -> None:
    r = CliRunner().invoke(main, ["schedule", *args])
    assert r.exit_code == 2 and r.output == LINE
    assert fake_launchd.calls == [] and not schedule.plist_path().exists()
    assert not schedule.LOG_DIR.exists() and not schedule.AGENTS_DIR.exists()


def test_other_commands_run_off_macos_as_before(linux: list, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli.scanner, "host", lambda: "host1")
    assert CliRunner().invoke(main, ["--help"]).exit_code == 0
    assert CliRunner().invoke(main, ["scan", "--help"]).exit_code == 0
    r = CliRunner().invoke(main, ["report"])
    assert r.exit_code == 1 and r.output == "no scan yet: run patched scan\n"  # its own answer, not macOS's


def test_the_system_name_is_the_systems_own(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mac, "system", lambda: ("freebsd14", "FreeBSD"))
    assert mac.off_macos() == "patched scans macOS only for now; this is FreeBSD."
    monkeypatch.setattr(mac, "system", lambda: ("darwin", "Darwin"))
    assert mac.off_macos() is None
