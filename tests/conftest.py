"""Suite-wide guards: no test reaches the real launchd or ~/Library.

Every launchctl call in patched goes through `schedule._launchctl`. The
autouse fixture swaps it for a FakeLaunchd and points schedule's three paths
at tmp_path, for EVERY test in the suite. A second layer fails closed: any
subprocess whose program is `launchctl` raises, so a call that skips
`_launchctl` (a new helper, a stray `subprocess.run`) cannot load an agent
either. os.system, posix_spawn(p) and the exec family skip Popen, so they
are guarded too. Everything else passes through untouched.
"""
from __future__ import annotations

import os
import plistlib
import subprocess
from pathlib import Path

import pytest

from patched import schedule

REAL_LAUNCHCTL = schedule._launchctl  # kept for the fail-closed test only
DEFAULTS = {k: getattr(schedule, k) for k in ("AGENTS_DIR", "LOG_DIR", "SCANS_DIR")}  # as imported


class LaunchdBlocked(AssertionError):
    """A test tried to run the real launchctl."""


def _is_launchctl(args) -> bool:
    """argv[0] is launchctl, in any form Popen takes: a list, a path, or a shell string."""
    if isinstance(args, (str, bytes)):
        first = (os.fsdecode(args).split() or [""])[0]
    elif isinstance(args, os.PathLike):
        first = os.fsdecode(args)
    else:
        argv = list(args or [])
        first = os.fsdecode(argv[0]) if argv else ""
    return os.path.basename(first) == "launchctl"


class GuardedPopen(subprocess.Popen):
    def __init__(self, args, *a, **kw):
        if _is_launchctl(args):
            raise LaunchdBlocked(f"test tried to run the real launchctl: {args!r}")
        super().__init__(args, *a, **kw)


def _guard_os(monkeypatch: pytest.MonkeyPatch) -> None:
    """The doors that skip Popen: os.system, posix_spawn(p) and the exec family
    (execvp/execlp and friends funnel into execv/execve). Each refuses launchctl."""
    real_system = os.system

    def system(command):
        if _is_launchctl(command):
            raise LaunchdBlocked(f"test tried to run the real launchctl: {command!r}")
        return real_system(command)
    monkeypatch.setattr(os, "system", system)

    def guard(name: str, argv_at: int) -> None:
        real = getattr(os, name)

        def wrapped(*args, **kw):
            if _is_launchctl([args[0]]) or _is_launchctl(list(args[argv_at])[:1]):
                raise LaunchdBlocked(f"test tried to run the real launchctl: os.{name}{args[:2]!r}")
            return real(*args, **kw)
        monkeypatch.setattr(os, name, wrapped)

    for name in ("posix_spawn", "posix_spawnp", "execv", "execve"):
        if hasattr(os, name):
            guard(name, 1)


NOT_FOUND ='Bad request.\nCould not find service "{label}" in domain for user gui: 501\n'
IO_ERROR = "Bootstrap failed: 5: Input/output error\n"


class FakeLaunchd:
    """One gui domain, as `schedule` sees it through `_launchctl(args)`.

    Records every call. `teardown` is how many `print` polls a booted-out job
    still answers as loaded; a `bootstrap` in that window fails the way real
    launchd is reported to (5: Input/output error), so the wait is tested.
    `fail[verb] = (rc, out)` makes the next call of that verb fail once.
    """

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.jobs: dict[str, dict] = {}
        self.tearing: dict[str, int] = {}
        self.teardown = 0
        self.fail: dict[str, tuple[int, str]] = {}

    def __call__(self, args: list[str]) -> tuple[int, str]:
        self.calls.append(list(args))
        verb = args[0]
        if verb in self.fail:
            return self.fail.pop(verb)
        if verb == "print":
            return self._print(args[1].rsplit("/", 1)[1])
        if verb == "bootstrap":
            label = plistlib.loads(Path(args[2]).read_bytes())["Label"]
            if label in self.jobs or label in self.tearing:
                return 5, IO_ERROR
            self.jobs[label] = {"plist": args[2], "runs": 0, "last_exit": "(never exited)"}
            return 0, ""
        if verb == "bootout":
            label = args[1].rsplit("/", 1)[1]
            if label not in self.jobs:
                return 3, "Boot-out failed: 3: No such process\n"
            del self.jobs[label]
            if self.teardown:
                self.tearing[label] = self.teardown
            return 0, ""
        return 64, f"Unrecognized subcommand: {verb}\n"

    def verbs(self) -> list[str]:
        return [c[0] for c in self.calls]

    def _print(self, label: str) -> tuple[int, str]:
        if label in self.tearing:
            if self.tearing[label] > 0:
                self.tearing[label] -= 1
                return 0, render_print(label, "/gone.plist", 0, "(never exited)")
            del self.tearing[label]
        job = self.jobs.get(label)
        if not job:
            return 113, NOT_FOUND.format(label=label)
        return 0, render_print(label, job["plist"], job["runs"], job["last_exit"])


def render_print(label: str, plist: str, runs: int, last_exit: str) -> str:
    """The shape of `launchctl print gui/501/<label>`, measured on a Mac (an
    existing calendar agent, read-only), trimmed. The nested `state = active`
    is the line parse_print must not take for the job's state."""
    return (f"gui/501/{label} = {{\n\tactive count = 0\n\tpath = {plist}\n\ttype = LaunchAgent\n"
            "\tstate = not running\n\n\tprogram = /x/patched\n\targuments = {\n\t\t/x/patched\n\t\tscan\n\t}\n\n"
            "\tdefault environment = {\n\t\tPATH => /usr/bin:/bin:/usr/sbin:/sbin\n\t}\n\n"
            "\tdomain = gui/501 [100022]\n\tminimum runtime = 10\n"
            f"\truns = {runs}\n\tlast exit code = {last_exit}\n\n"
            f"\tevent triggers = {{\n\t\t{label}.268435471 => {{\n\t\t\tstate = active\n"
            "\t\t\tstream = com.apple.launchd.calendarinterval\n\t\t}\n\t}\n\n"
            "\tjob state = uninitialized\n}\n")


@pytest.fixture(autouse=True)
def fake_launchd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeLaunchd:
    fake = FakeLaunchd()
    monkeypatch.setattr(schedule, "_launchctl", fake)
    monkeypatch.setattr(subprocess, "Popen", GuardedPopen)
    _guard_os(monkeypatch)
    root = tmp_path / "_schedule"
    monkeypatch.setattr(schedule, "AGENTS_DIR", root / "LaunchAgents")
    monkeypatch.setattr(schedule, "LOG_DIR", root / "Logs/patched")
    monkeypatch.setattr(schedule, "SCANS_DIR", root / "scans")
    return fake


@pytest.fixture
def real_launchctl():
    """The unpatched `_launchctl`, for proving it cannot reach launchd."""
    return REAL_LAUNCHCTL
