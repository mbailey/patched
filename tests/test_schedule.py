"""patched schedule: the plist, the agent's PATH, on/off/status.

launchd is FakeLaunchd (tests/conftest.py, autouse): no test here, or anywhere
in the suite, can load a real agent or touch ~/Library.
"""
from __future__ import annotations

import ast
import json
import os
import plistlib
import shutil
import subprocess
from pathlib import Path

import pytest
from conftest import DEFAULTS, FakeLaunchd, LaunchdBlocked, render_print

from patched import collect, net, schedule
from patched import scan as scanner


def exe(d: Path, *names: str) -> Path:
    d.mkdir(parents=True, exist_ok=True)
    for n in names:
        f = d / n
        f.write_text("#!/bin/sh\nexit 0\n")
        f.chmod(0o755)
    return d


@pytest.fixture
def env(tmp_path: Path) -> dict[str, str]:
    """A user env as a Mac splits it: uv and patched in ~/.local/bin, the rest in brew's bin."""
    home = tmp_path / "home"
    local = exe(home / ".local/bin", "uv", "patched")
    brew = exe(tmp_path / "brew/bin", "brew", "npm", "tailscale", "git")
    sysbin = exe(tmp_path / "sys", "lsof", "ps", "sw_vers", "fdesetup", "csrutil", "spctl")
    textfile = tmp_path / "textfile"
    textfile.mkdir()
    return {"HOME": str(home), "PATH": os.pathsep.join(map(str, (local, brew, sysbin))),
            "PATCHED_TEXTFILE_DIR": str(textfile)}


# --- the guard: no test reaches launchd ---

def test_the_suite_never_reaches_the_real_launchctl(real_launchctl) -> None:
    """The unpatched door fails closed: GuardedPopen refuses argv[0] launchctl."""
    with pytest.raises(LaunchdBlocked):
        real_launchctl(["print", "gui/501/com.failmode.patched-scan"])


@pytest.mark.parametrize("args", [["launchctl", "list"], ["/bin/launchctl", "bootstrap", "gui/501", "x"],
                                  "launchctl bootout gui/501/x", Path("/bin/launchctl")])
def test_any_launchctl_subprocess_is_refused(args) -> None:
    with pytest.raises(LaunchdBlocked):
        subprocess.run(args, shell=isinstance(args, str), check=False)


@pytest.fixture
def decoy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    """A fake launchctl first on PATH that only touches a marker: if a door
    leaks, the decoy runs (harmless) and the marker says so."""
    d, marker = tmp_path / "decoy", tmp_path / "decoy-ran"
    d.mkdir()
    (d / "launchctl").write_text(f"#!/bin/sh\n/usr/bin/touch {marker}\n")
    (d / "launchctl").chmod(0o755)
    monkeypatch.setenv("PATH", f"{d}{os.pathsep}{os.environ['PATH']}")
    return d / "launchctl", marker


def test_os_system_launchctl_is_refused(decoy: tuple[Path, Path]) -> None:
    _, marker = decoy
    with pytest.raises(LaunchdBlocked):
        os.system("launchctl print gui/501/x")
    assert not marker.exists()


@pytest.mark.parametrize("spawn", ["posix_spawn", "posix_spawnp"])
def test_posix_spawn_launchctl_is_refused(decoy: tuple[Path, Path], spawn: str) -> None:
    path, marker = decoy
    with pytest.raises(LaunchdBlocked):
        getattr(os, spawn)(str(path) if spawn == "posix_spawn" else "launchctl", ["launchctl", "list"], os.environ)
    assert not marker.exists()


@pytest.mark.parametrize("call", [lambda: os.execv("/nonexistent/launchctl", ["launchctl"]),
                                  lambda: os.execve("/nonexistent/launchctl", ["launchctl"], {}),
                                  lambda: os.execvp("launchctl", ["launchctl", "list"])])
def test_exec_launchctl_is_refused(call, monkeypatch: pytest.MonkeyPatch) -> None:
    """Paths that do not exist (execvp searches a PATH of none): a leak raises
    FileNotFoundError, and never replaces pytest with a real launchctl."""
    monkeypatch.setenv("PATH", "/nonexistent/a:/nonexistent/b")
    with pytest.raises(LaunchdBlocked):
        call()


def test_other_subprocesses_still_run() -> None:
    assert subprocess.run(["true"], check=False).returncode == 0
    assert os.system("true") == 0


def test_verbs_go_through_the_fake_and_tmp_paths(fake_launchd: FakeLaunchd, env: dict) -> None:
    schedule.on(env=env)
    assert fake_launchd.verbs() == ["print", "bootstrap"]
    assert schedule._launchctl is fake_launchd
    home = Path.home()
    for p in (schedule.AGENTS_DIR, schedule.LOG_DIR, schedule.SCANS_DIR):
        assert home / "Library" not in p.parents and "_schedule" in p.parts


# --- the plist ---

def test_render_plist_carries_every_key(env: dict) -> None:
    agent_env = schedule.environment(env)
    p = plistlib.loads(schedule.render_plist("/u/.local/bin/patched", agent_env))
    log = str(schedule.LOG_DIR / "scan.log")
    assert p == {
        "Label": "com.failmode.patched-scan",
        "ProgramArguments": ["/u/.local/bin/patched", "scan", "--quiet"],
        "StartCalendarInterval": {"Minute": 7},
        "RunAtLoad": True,
        "ProcessType": "Background",
        "StandardOutPath": log,
        "StandardErrorPath": log,
        "EnvironmentVariables": agent_env,
    }


def test_render_plist_is_stable_bytes(env: dict) -> None:
    e = schedule.environment(env)
    assert schedule.render_plist("/p", e) == schedule.render_plist("/p", dict(reversed(list(e.items()))))


def test_resolve_patched_takes_the_path_as_found(env: dict, tmp_path: Path) -> None:
    real = exe(tmp_path / "tools/patched/bin", "patched") / "patched"
    link = Path(env["HOME"]) / ".local/bin/patched"
    link.unlink()
    link.symlink_to(real)
    program, warning = schedule.resolve_patched(env["PATH"])
    assert program == str(link) and warning is None  # the symlink, not its target


def test_resolve_patched_falls_back_to_argv0(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(schedule.sys, "argv", ["bin/patched"])
    monkeypatch.chdir(tmp_path)
    program, _ = schedule.resolve_patched(str(tmp_path / "empty"))
    assert program == str(tmp_path / "bin/patched")


def test_resolve_patched_warns_on_a_venv(tmp_path: Path) -> None:
    d = exe(tmp_path / "checkout/.venv/bin", "patched")
    program, warning = schedule.resolve_patched(str(d))
    assert program == str(d / "patched")
    assert warning and ".venv" in warning and program in warning


def test_only_set_behaviour_vars_are_carried(env: dict) -> None:
    e = schedule.environment(env | {"PATCHED_HOME": "/h", "UNRELATED": "x"})
    assert set(e) == {"PATH", "PATCHED_TEXTFILE_DIR", "PATCHED_HOME"}
    assert e["PATCHED_HOME"] == "/h"
    assert "HOME" not in e  # launchd sets it for a gui agent


# --- PATH: the agent's scan sees what a hand run sees ---

def test_agent_path_resolves_every_tool_as_the_user_path_does(env: dict) -> None:
    agent = schedule.environment(env)["PATH"]
    for t in collect.TOOLS:
        assert shutil.which(t, path=agent) == shutil.which(t, path=env["PATH"]), t
    assert schedule.missing_tools(agent) == []


def test_agent_path_keeps_the_user_order_then_the_floor(env: dict, tmp_path: Path) -> None:
    user = env["PATH"].split(os.pathsep)
    messy = os.pathsep.join([user[0], "relative/bin", str(tmp_path / "missing"), user[0], *user[1:]])
    got = schedule.agent_path(messy, env).split(os.pathsep)
    assert got[:3] == user
    assert "relative/bin" not in got and str(tmp_path / "missing") not in got
    assert user[0] == f"{env['HOME']}/.local/bin"  # already there, so the floor skips it
    assert got[3:] == ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"]


def test_from_launchds_default_path_the_floor_finds_uv_brew_npm(tmp_path: Path) -> None:
    """An `on` from a stripped shell (cron, ssh) still schedules a seeing scan."""
    home, prefix = tmp_path / "home", tmp_path / "homebrew"
    exe(home / ".local/bin", "uv")
    exe(prefix / "bin", "brew", "npm")
    stripped = {"HOME": str(home), "HOMEBREW_PREFIX": str(prefix), "PATH": schedule.LAUNCHD_PATH}
    agent = schedule.environment(stripped)["PATH"]
    assert shutil.which("uv", path=agent) == str(home / ".local/bin/uv")
    assert shutil.which("brew", path=agent) == str(prefix / "bin/brew")
    assert shutil.which("npm", path=agent) == str(prefix / "bin/npm")


def _commands(source: str) -> set[str]:
    """Names collect.py runs: the first element of a list passed to run()/subprocess.run(),
    or at the head of a tuple (the protections() table). Absolute paths need no PATH."""
    names = set()
    for node in ast.walk(ast.parse(source)):
        lists = []
        if isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", None)) == "run":
            lists = node.args[:1]
        elif isinstance(node, ast.Tuple) and node.elts:
            lists = node.elts[:1]
        for lst in lists:
            if (isinstance(lst, ast.List) and lst.elts and isinstance(lst.elts[0], ast.Constant)
                    and isinstance(lst.elts[0].value, str) and not lst.elts[0].value.startswith("/")):
                names.add(lst.elts[0].value)
    return names


def test_every_command_collect_runs_is_in_tools() -> None:
    """Drift guard: a new source cannot slip past the PATH check."""
    found = _commands(Path(collect.__file__).read_text())
    assert {"brew", "uv", "npm", "tailscale", "git", "fdesetup", "csrutil", "spctl"} <= found  # the guard sees them
    assert found <= set(collect.TOOLS), found - set(collect.TOOLS)


def test_the_drift_guard_catches_a_new_command() -> None:
    src = 'def f():\n    run(["mas", "list"])\n    x = (["newtool", "-v"], r"on", r"off")\n    item("x", ["PyPI", n, v])\n'
    assert _commands(src) == {"mas", "newtool"}


def test_missing_tools_names_each_gap(env: dict) -> None:
    only_sys = env["PATH"].split(os.pathsep)[2]
    assert schedule.missing_tools(only_sys) == ["brew", "uv", "git", "npm", "tailscale"]


# --- on ---

def test_on_writes_loads_and_makes_the_log_dir(fake_launchd: FakeLaunchd, env: dict) -> None:
    r = schedule.on(env=env)
    assert r["action"] == "loaded"
    assert fake_launchd.calls[-1] == ["bootstrap", f"gui/{os.getuid()}", str(schedule.plist_path())]
    assert schedule.LOG_DIR.is_dir()
    p = plistlib.loads(schedule.plist_path().read_bytes())
    assert p["ProgramArguments"][0] == f"{env['HOME']}/.local/bin/patched"
    assert oct(schedule.plist_path().stat().st_mode & 0o777) == "0o644"
    assert r["missing"] == [] and r["log"] == str(schedule.LOG_DIR / "scan.log")


def test_a_second_on_is_already_on(fake_launchd: FakeLaunchd, env: dict) -> None:
    schedule.on(env=env)
    fake_launchd.calls.clear()
    assert schedule.on(env=env)["action"] == "already on"
    assert fake_launchd.verbs() == ["print"]  # no second bootstrap


def test_a_changed_plist_is_booted_out_waited_for_then_bootstrapped(fake_launchd: FakeLaunchd, env: dict) -> None:
    schedule.on(env=env)
    fake_launchd.calls.clear()
    fake_launchd.teardown = 2  # the old job answers print twice more after bootout
    r = schedule.on(env=env | {"PATCHED_DETAIL_SERIES": "1"})
    assert r["action"] == "reloaded"
    assert fake_launchd.verbs() == ["print", "bootout", "print", "print", "print", "bootstrap"]
    p = plistlib.loads(schedule.plist_path().read_bytes())
    assert p["EnvironmentVariables"]["PATCHED_DETAIL_SERIES"] == "1"


def test_without_the_wait_bootstrap_hits_the_io_error(fake_launchd: FakeLaunchd, env: dict,
                                                       monkeypatch: pytest.MonkeyPatch) -> None:
    """Why the wait exists: the fake models launchd's 5: Input/output error."""
    schedule.on(env=env)
    fake_launchd.teardown = 2
    monkeypatch.setattr(schedule, "_wait_gone", lambda wait: None)
    with pytest.raises(schedule.ScheduleError, match="5: Input/output error"):
        schedule.on(env=env | {"PATCHED_DETAIL_SERIES": "1"})


def test_the_wait_is_bounded(fake_launchd: FakeLaunchd, env: dict) -> None:
    schedule.on(env=env)
    fake_launchd.teardown = 10**6
    with pytest.raises(schedule.ScheduleError, match="still loaded"):
        schedule.on(env=env | {"PATCHED_DETAIL_SERIES": "1"}, wait=0.2)
    assert "bootstrap" not in fake_launchd.verbs()[2:]


def test_on_reloads_when_the_plist_is_there_but_not_loaded(fake_launchd: FakeLaunchd, env: dict) -> None:
    schedule.on(env=env)
    fake_launchd.jobs.clear()  # e.g. booted out by hand
    fake_launchd.calls.clear()
    assert schedule.on(env=env)["action"] == "loaded"
    assert fake_launchd.verbs() == ["print", "bootstrap"]


def test_on_refuses_a_missing_textfile_dir(fake_launchd: FakeLaunchd, env: dict, tmp_path: Path) -> None:
    gone = tmp_path / "no-such-dir"
    with pytest.raises(schedule.ScheduleError, match=str(gone)):
        schedule.on(env=env | {"PATCHED_TEXTFILE_DIR": str(gone)})
    assert fake_launchd.calls == [] and not schedule.plist_path().exists()


def test_on_dry_run_writes_and_loads_nothing(fake_launchd: FakeLaunchd, env: dict) -> None:
    r = schedule.on(dry_run=True, env=env)
    assert r["action"] == "dry-run" and "com.failmode.patched-scan" in r["text"]
    assert fake_launchd.calls == []
    assert not schedule.plist_path().exists() and not schedule.LOG_DIR.exists()


@pytest.fixture
def no_floor(monkeypatch: pytest.MonkeyPatch) -> None:
    """This Mac's real /opt/homebrew/bin and /usr/bin would fill any gap: take the floor away."""
    monkeypatch.setattr(schedule, "floor", lambda env: [])


@pytest.mark.usefixtures("no_floor")
def test_on_reports_tools_the_agent_would_miss(fake_launchd: FakeLaunchd, env: dict, tmp_path: Path) -> None:
    for t in ("npm", "tailscale"):
        (tmp_path / "brew/bin" / t).unlink()
    assert schedule.on(env=env)["missing"] == ["npm", "tailscale"]  # warned, not refused


def test_on_carries_a_venv_warning(fake_launchd: FakeLaunchd, env: dict, tmp_path: Path) -> None:
    venv = exe(tmp_path / "co/.venv/bin", "patched")
    r = schedule.on(env=env | {"PATH": f"{venv}{os.pathsep}{env['PATH']}"})
    assert r["action"] == "loaded" and ".venv" in r["warnings"][0]


def test_on_writes_atomically(fake_launchd: FakeLaunchd, env: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    schedule.on(env=env)
    before = schedule.plist_path().read_bytes()

    def boom(src, dst):
        raise OSError("disk full")
    monkeypatch.setattr(schedule.os, "replace", boom)
    with pytest.raises(OSError):
        schedule.on(env=env | {"PATCHED_DETAIL_SERIES": "1"})
    assert schedule.plist_path().read_bytes() == before  # never half a plist


def test_a_failed_bootstrap_is_reported(fake_launchd: FakeLaunchd, env: dict) -> None:
    fake_launchd.fail["bootstrap"] = (1, "Bootstrap failed: 1: Operation not permitted\n")
    with pytest.raises(schedule.ScheduleError, match="bootstrap exited 1: .*not permitted"):
        schedule.on(env=env)


def test_an_unexpected_print_failure_is_not_read_as_unloaded(fake_launchd: FakeLaunchd, env: dict) -> None:
    fake_launchd.fail["print"] = (127, "No such file or directory: 'launchctl'")
    with pytest.raises(schedule.ScheduleError, match="print exited 127"):
        schedule.off()


# --- off ---

def test_off_unloads_and_removes(fake_launchd: FakeLaunchd, env: dict) -> None:
    schedule.on(env=env)
    fake_launchd.calls.clear()
    assert schedule.off()["action"] == "off"
    assert fake_launchd.verbs() == ["print", "bootout"]
    assert not schedule.plist_path().exists() and not fake_launchd.jobs


def test_off_with_nothing_installed_is_already_off(fake_launchd: FakeLaunchd) -> None:
    assert schedule.off()["action"] == "already off"
    assert schedule.off()["action"] == "already off"
    assert fake_launchd.verbs() == ["print", "print"]


def test_off_removes_a_plist_that_is_not_loaded(fake_launchd: FakeLaunchd, env: dict) -> None:
    schedule.on(env=env)
    fake_launchd.jobs.clear()
    assert schedule.off()["action"] == "off" and not schedule.plist_path().exists()
    assert "bootout" not in fake_launchd.verbs()


def test_a_bootout_error_on_a_loaded_job_keeps_the_plist(fake_launchd: FakeLaunchd, env: dict) -> None:
    schedule.on(env=env)
    fake_launchd.fail["bootout"] = (5, "Boot-out failed: 5: Input/output error\n")
    with pytest.raises(schedule.ScheduleError, match="bootout exited 5.*left in place"):
        schedule.off()
    assert schedule.plist_path().exists()


# --- status ---

def test_parse_print_takes_top_level_lines_only() -> None:
    got = schedule.parse_print(render_print("x", "/p.plist", 3, "0"))
    assert got["state"] == "not running"  # not the nested trigger's `state = active`
    assert got["runs"] == "3" and got["last exit code"] == "0" and got["path"] == "/p.plist"
    assert "arguments" not in got and "event triggers" not in got and "PATH" not in got
    assert got["job state"] == "uninitialized"


def test_status_when_off(fake_launchd: FakeLaunchd, env: dict) -> None:
    s = schedule.status(env=env)
    assert s["loaded"] is False and s["installed"] is False and s["state"] is None
    assert s["log"] == str(schedule.LOG_DIR / "scan.log") and s["log_size"] is None
    assert s["last_scan"] is None and s["drift"] == {} and s["missing"] == []


def _record(stamp: str, started: float, finished: float, stages: dict) -> None:
    schedule.SCANS_DIR.mkdir(parents=True, exist_ok=True)
    (schedule.SCANS_DIR / f"host1-{stamp}.json").write_text(
        json.dumps({"stamp": stamp, "started": started, "finished": finished, "stages": stages}))


def test_status_when_on(fake_launchd: FakeLaunchd, env: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scanner, "host", lambda: "host1")
    schedule.on(env=env)
    job = fake_launchd.jobs[schedule.LABEL]
    job["runs"], job["last_exit"] = 4, "1"
    schedule.log_path().write_text("90 items: ...\nwrote /t/patched.prom (...)\nFAILED stages: osv: {}\n\n")
    _record("20261029T140000", 100.0, 110.0, {"brew": True})
    _record("20261029T150000", 200.0, 217.84, {"brew": True, "osv": False})
    (schedule.SCANS_DIR / "other-20261029T160000.json").write_text("{}")  # another host's: ignored
    prom = Path(env["PATCHED_TEXTFILE_DIR"]) / "patched.prom"
    prom.write_text("x\n")
    s = schedule.status(env=env)
    assert (s["loaded"], s["installed"], s["state"], s["runs"], s["last_exit"]) == (True, True, "not running", "4", "1")
    assert s["program"] == [f"{env['HOME']}/.local/bin/patched", "scan", "--quiet"]
    assert s["log_last"] == "FAILED stages: osv: {}" and s["log_size"] > 0
    assert s["last_scan"]["stamp"] == "20261029T150000" and s["last_scan"]["seconds"] == 17.8
    assert s["last_scan"]["failed"] == ["osv"]
    assert s["prom"] == str(prom) and s["prom_mtime"] == prom.stat().st_mtime
    assert s["missing"] == [] and s["drift"] == {}


@pytest.mark.usefixtures("no_floor")
def test_status_names_env_drift_and_missing_tools(fake_launchd: FakeLaunchd, env: dict, tmp_path: Path) -> None:
    schedule.on(env=env)
    (tmp_path / "brew/bin/tailscale").unlink()
    s = schedule.status(env=env | {"PATCHED_DETAIL_SERIES": "1"})
    assert s["drift"] == {"PATCHED_DETAIL_SERIES": {"shell": "1", "plist": None}}
    assert s["missing"] == ["tailscale"]


def test_status_reads_an_unreadable_record_as_an_error(fake_launchd: FakeLaunchd,
                                                       monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scanner, "host", lambda: "host1")
    schedule.SCANS_DIR.mkdir(parents=True)
    (schedule.SCANS_DIR / "host1-20261029T150000.json").write_text("{half")
    assert "error" in schedule.status(env={})["last_scan"]


def test_module_paths_default_to_the_real_places() -> None:
    """As imported, before the autouse fixture redirects them: SCANS_DIR is where
    export.write_record writes (net.HOME / scans), so PATCHED_HOME moves both."""
    assert DEFAULTS["SCANS_DIR"] == net.HOME / "scans"
    assert DEFAULTS["AGENTS_DIR"] == Path.home() / "Library/LaunchAgents"
    assert DEFAULTS["LOG_DIR"] == Path.home() / "Library/Logs/patched"
