"""`patched schedule on|off|status` through the CLI.

launchd is FakeLaunchd and schedule's paths are tmp_path (tests/conftest.py,
autouse): nothing here can load a real agent or write ~/Library.
"""
from __future__ import annotations

import os
import plistlib
import time
from pathlib import Path

import pytest
from click.testing import CliRunner
from conftest import FakeLaunchd

from patched import scan as scanner
from patched import schedule
from patched.cli import main


def exe(d: Path, *names: str) -> Path:
    d.mkdir(parents=True, exist_ok=True)
    for n in names:
        (d / n).write_text("#!/bin/sh\nexit 0\n")
        (d / n).chmod(0o755)
    return d


@pytest.fixture
def shell(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    """The user's shell as a Mac has it: patched and uv in ~/.local/bin, the rest in brew's bin."""
    home = tmp_path / "home"
    local = exe(home / ".local/bin", "patched", "uv")
    brew = exe(tmp_path / "brew/bin", "brew", "npm", "tailscale", "git")
    sysbin = exe(tmp_path / "sys", "lsof", "ps", "sw_vers", "fdesetup", "csrutil", "spctl")
    textfile = tmp_path / "textfile"
    textfile.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("PATH", os.pathsep.join(map(str, (local, brew, sysbin))))
    monkeypatch.setenv("PATCHED_TEXTFILE_DIR", str(textfile))
    for k in ("PATCHED_DETAIL_SERIES", "PATCHED_HOME", "PATCHED_CONFIG", "PATCHED_ALLOW_SERVICES",
              "HOMEBREW_PREFIX"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(scanner, "host", lambda: "host1")
    return {"home": home, "brew": tmp_path / "brew/bin", "textfile": textfile}


@pytest.fixture
def no_floor(monkeypatch: pytest.MonkeyPatch) -> None:
    """This Mac's real /opt/homebrew/bin would fill any gap: take the floor away."""
    monkeypatch.setattr(schedule, "floor", lambda env: [])


def run(*args: str):
    return CliRunner().invoke(main, ["schedule", *args])


def test_help_lists_the_three_verbs() -> None:
    r = run("--help")
    assert r.exit_code == 0
    for verb in ("on", "off", "status"):
        assert f"  {verb} " in r.output
    assert "Nothing is scheduled until you run `patched schedule on`" in r.output
    assert "schedule" in CliRunner().invoke(main, ["--help"]).output


# --- on ---

def test_on_loads_and_says_what_and_where(fake_launchd: FakeLaunchd, shell: dict) -> None:
    r = run("on")
    assert r.exit_code == 0, r.output
    assert f"loaded: com.failmode.patched-scan ({schedule.plist_path()})" in r.output
    assert f"runs: {shell['home']}/.local/bin/patched scan --quiet, hourly at :07 and at load" in r.output
    assert f"log: {schedule.LOG_DIR / 'scan.log'}" in r.output
    assert fake_launchd.verbs() == ["print", "bootstrap"]
    assert "warning" not in r.output


def test_a_second_on_is_already_on_exit_0(fake_launchd: FakeLaunchd, shell: dict) -> None:
    run("on")
    fake_launchd.calls.clear()
    r = run("on")
    assert r.exit_code == 0 and r.output.startswith("already on: com.failmode.patched-scan")
    assert fake_launchd.verbs() == ["print"]


def test_on_after_a_change_reloads(fake_launchd: FakeLaunchd, shell: dict,
                                   monkeypatch: pytest.MonkeyPatch) -> None:
    run("on")
    monkeypatch.setenv("PATCHED_DETAIL_SERIES", "1")
    r = run("on")
    assert r.exit_code == 0 and r.output.startswith("reloaded:")
    assert plistlib.loads(schedule.plist_path().read_bytes())["EnvironmentVariables"]["PATCHED_DETAIL_SERIES"] == "1"


def test_on_dry_run_prints_the_plist_and_writes_and_loads_nothing(fake_launchd: FakeLaunchd,
                                                                  shell: dict) -> None:
    r = run("on", "-n")
    assert r.exit_code == 0, r.output
    p = plistlib.loads(r.stdout.encode())
    assert p["Label"] == "com.failmode.patched-scan" and p["ProgramArguments"][1:] == ["scan", "--quiet"]
    assert "nothing written, nothing loaded" in r.stderr
    assert fake_launchd.calls == []
    assert not schedule.plist_path().exists() and not schedule.LOG_DIR.exists()
    assert not schedule.AGENTS_DIR.exists()


def test_on_carries_keep_days_when_set_and_only_then(fake_launchd: FakeLaunchd, shell: dict,
                                                      monkeypatch: pytest.MonkeyPatch) -> None:
    """PATCHED_KEEP_DAYS=0 keeps every record by hand; the hourly agent must keep them too."""
    monkeypatch.delenv("PATCHED_KEEP_DAYS", raising=False)
    r = run("on", "-n")
    assert r.exit_code == 0, r.output
    assert "PATCHED_KEEP_DAYS" not in plistlib.loads(r.stdout.encode())["EnvironmentVariables"]
    monkeypatch.setenv("PATCHED_KEEP_DAYS", "0")
    r = run("on", "-n")
    assert r.exit_code == 0, r.output
    assert plistlib.loads(r.stdout.encode())["EnvironmentVariables"]["PATCHED_KEEP_DAYS"] == "0"


def test_on_refuses_a_missing_textfile_dir_exit_1(fake_launchd: FakeLaunchd, shell: dict,
                                                  monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("PATCHED_TEXTFILE_DIR", str(tmp_path / "nope"))
    r = run("on")
    assert r.exit_code == 1
    assert f"textfile dir {tmp_path / 'nope'} does not exist" in r.output and "Traceback" not in r.output
    assert fake_launchd.calls == [] and not schedule.plist_path().exists()


@pytest.fixture
def no_default(shell: dict, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """No node_exporter: nobody named a textfile dir, and the default is missing."""
    default = tmp_path / "no-node-exporter"
    monkeypatch.setattr(schedule.export, "DEFAULT_TEXTFILE_DIR", default)
    monkeypatch.setattr(schedule.export, "TEXTFILE_DIR", default)
    monkeypatch.delenv("PATCHED_TEXTFILE_DIR")
    return default


def test_on_without_node_exporter_loads_and_warns_once(fake_launchd: FakeLaunchd, no_default: Path) -> None:
    r = run("on")
    assert r.exit_code == 0, r.output
    assert r.stdout.startswith("loaded: com.failmode.patched-scan")
    line = (f"warning: no patched.prom will be written ({no_default} is missing); "
            "each scan still saves its record")
    assert r.stderr.splitlines().count(line) == 1
    assert fake_launchd.verbs() == ["print", "bootstrap"] and schedule.plist_path().exists()
    assert not no_default.exists()


def test_status_without_node_exporter_says_none_and_why(fake_launchd: FakeLaunchd, no_default: Path) -> None:
    r = run("status")
    assert r.exit_code == 0, r.output
    assert f"patched.prom: none ({no_default} is missing)" in r.output
    assert "patched.prom: -" not in r.output
    run("on")
    assert f"patched.prom: none ({no_default} is missing)" in run("status").output  # the agent's dir too


def test_a_failed_bootstrap_is_one_line_exit_1(fake_launchd: FakeLaunchd, shell: dict) -> None:
    fake_launchd.fail["bootstrap"] = (1, "Bootstrap failed: 1: Operation not permitted\n")
    r = run("on")
    assert r.exit_code == 1 and "bootstrap exited 1" in r.output and "Traceback" not in r.output


@pytest.mark.usefixtures("no_floor")
def test_on_warns_for_tools_the_agent_would_miss_but_loads(fake_launchd: FakeLaunchd, shell: dict) -> None:
    (shell["brew"] / "npm").unlink()
    (shell["brew"] / "tailscale").unlink()
    r = run("on")
    assert r.exit_code == 0 and r.output.startswith("loaded:")
    assert "warning: not on the agent's PATH: npm, tailscale" in r.stderr


def test_on_warns_on_a_venv_patched(fake_launchd: FakeLaunchd, shell: dict, tmp_path: Path,
                                    monkeypatch: pytest.MonkeyPatch) -> None:
    venv = exe(tmp_path / "co/.venv/bin", "patched")
    monkeypatch.setenv("PATH", f"{venv}{os.pathsep}{os.environ['PATH']}")
    r = run("on")
    assert r.exit_code == 0 and "warning:" in r.stderr and ".venv" in r.stderr


# --- off ---

def test_off_unloads_and_removes(fake_launchd: FakeLaunchd, shell: dict) -> None:
    run("on")
    r = run("off")
    assert r.exit_code == 0 and r.output.startswith("off: com.failmode.patched-scan")
    assert not schedule.plist_path().exists() and not fake_launchd.jobs


def test_off_with_nothing_installed_and_a_second_off_exit_0(fake_launchd: FakeLaunchd, shell: dict) -> None:
    for _ in range(2):
        r = run("off")
        assert r.exit_code == 0 and r.output.startswith("already off:")
    assert "bootout" not in fake_launchd.verbs()


def test_off_reports_a_real_bootout_error_exit_1(fake_launchd: FakeLaunchd, shell: dict) -> None:
    run("on")
    fake_launchd.fail["bootout"] = (5, "Boot-out failed: 5: Input/output error\n")
    r = run("off")
    assert r.exit_code == 1 and "bootout exited 5" in r.output and "left in place" in r.output
    assert schedule.plist_path().exists()


# --- status ---

def test_status_when_off(fake_launchd: FakeLaunchd, shell: dict) -> None:
    r = run("status")
    assert r.exit_code == 0, r.output
    assert "com.failmode.patched-scan: not loaded" in r.output
    assert "(not installed)" in r.output
    assert f"log: {schedule.LOG_DIR / 'scan.log'} (none yet)" in r.output
    assert "last run: none" in r.output and "patched.prom: -" in r.output


def test_status_when_on_names_loaded_last_run_exit_code_and_log(fake_launchd: FakeLaunchd,
                                                                shell: dict) -> None:
    run("on")
    job = fake_launchd.jobs[schedule.LABEL]
    job["runs"], job["last_exit"] = 3, "1"
    schedule.log_path().write_text("90 items: ...\nFAILED stages: osv: {}\n")
    schedule.SCANS_DIR.mkdir(parents=True)
    started = time.time() - 600
    (schedule.SCANS_DIR / "host1-20261029T150000.json").write_text(
        f'{{"stamp": "20261029T150000", "started": {started}, "finished": {started + 17.84}, '
        '"stages": {"brew": true, "osv": false}}')
    (shell["textfile"] / "patched.prom").write_text("x\n")
    r = run("status")
    assert r.exit_code == 0, r.output
    assert "com.failmode.patched-scan: loaded (state not running, runs 3, last exit code 1)" in r.output
    assert f"program: {shell['home']}/.local/bin/patched scan --quiet" in r.output
    assert f"log: {schedule.log_path()} (" in r.output and "last line: FAILED stages: osv: {}" in r.output
    stamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(started))
    assert f"last run: {stamp} (10 min ago), 17.8 s; failed: osv (any scan, by hand or the agent)" in r.output
    assert "patched.prom: " in r.output and "min ago" in r.output.split("patched.prom: ")[1]
    assert "warning" not in r.output


@pytest.mark.usefixtures("no_floor")
def test_status_warns_of_drift_and_missing_tools(fake_launchd: FakeLaunchd, shell: dict,
                                                 monkeypatch: pytest.MonkeyPatch) -> None:
    run("on")
    (shell["brew"] / "tailscale").unlink()
    monkeypatch.setenv("PATCHED_DETAIL_SERIES", "1")
    r = run("status")
    assert r.exit_code == 0
    assert "warning: not on the agent's PATH: tailscale" in r.stderr
    assert "warning: PATCHED_DETAIL_SERIES is '1' in this shell, None in the agent" in r.stderr


def test_status_on_a_launchctl_failure_is_exit_1(fake_launchd: FakeLaunchd, shell: dict) -> None:
    fake_launchd.fail["print"] = (127, "No such file or directory: 'launchctl'")
    r = run("status")
    assert r.exit_code == 1 and "print exited 127" in r.output and "Traceback" not in r.output


def test_status_reads_the_agents_prom_not_the_shells(fake_launchd: FakeLaunchd, shell: dict,
                                                      monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """An agent installed without PATCHED_TEXTFILE_DIR writes to the built-in default,
    whatever this shell sets now."""
    default = tmp_path / "default-textfile"
    default.mkdir()
    monkeypatch.setattr(schedule.export, "DEFAULT_TEXTFILE_DIR", default)
    monkeypatch.setattr(schedule.export, "TEXTFILE_DIR", default)
    monkeypatch.delenv("PATCHED_TEXTFILE_DIR")
    assert run("on").exit_code == 0  # no PATCHED_TEXTFILE_DIR carried
    monkeypatch.setenv("PATCHED_TEXTFILE_DIR", str(shell["textfile"]))
    monkeypatch.setattr(schedule.export, "TEXTFILE_DIR", shell["textfile"])  # as an import under this shell sees it
    r = run("status")
    assert f"({default / 'patched.prom'})" in r.output
    assert "PATCHED_TEXTFILE_DIR is" in r.stderr  # and the drift is named
