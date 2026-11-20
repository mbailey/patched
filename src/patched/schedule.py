"""patched schedule: an hourly `patched scan` as a user LaunchAgent.

No sudo: the agent is the user's, in gui/<uid>, its plist in
~/Library/LaunchAgents. Every launchctl call goes through ONE function,
`_launchctl`, so the suite fakes that and nothing else (tests/conftest.py).
The verbs return data; the CLI prints it and picks the exit code.

The agent runs the `patched` found on the user's PATH at `on` time, with that
PATH (plus a floor) in the plist: launchd's own default PATH has no
~/.local/bin or Homebrew's bin (/opt/homebrew/bin; /usr/local/bin on an
Intel Mac), and `collect.run` reads a missing tool as an empty source,
silently.
"""
from __future__ import annotations

import json
import os
import plistlib
import shutil
import subprocess
import sys
import time
from collections.abc import Mapping
from pathlib import Path

from . import collect, export, mac, net
from . import scan as scanner

LABEL = "com.failmode.patched-scan"
AGENTS_DIR = Path.home() / "Library/LaunchAgents"
LOG_DIR = Path.home() / "Library/Logs/patched"
SCANS_DIR = net.HOME / "scans"  # where export.write_record puts them; PATCHED_HOME moves both
MINUTE = 7  # every hour at :07
LAUNCHD_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
# Behaviour vars carried into the plist when SET at `on` time; unset ones keep their defaults.
CARRIED = ("PATCHED_TEXTFILE_DIR", "PATCHED_DETAIL_SERIES", "PATCHED_HOME",
           "PATCHED_CONFIG", "PATCHED_ALLOW_SERVICES", "PATCHED_KEEP_DAYS", "HOMEBREW_PREFIX")
GONE = 113  # `launchctl print`: no such service
WAIT = 5.0  # seconds a booted-out job gets to go before bootstrap
POLL = 0.1


class ScheduleError(RuntimeError):
    """launchctl refused, or `on` would schedule a scan that cannot run."""


def _launchctl(args: list[str]) -> tuple[int, str]:
    """The one door to launchd: (exit code, stdout + stderr)."""
    try:
        p = subprocess.run(["launchctl", *args], capture_output=True, text=True, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, str(e)
    return p.returncode, p.stdout + p.stderr


def plist_path() -> Path:
    return AGENTS_DIR / f"{LABEL}.plist"


def log_path() -> Path:
    return LOG_DIR / "scan.log"


def target() -> str:
    return f"gui/{os.getuid()}/{LABEL}"


# --- pure helpers ---

def resolve_patched(path: str | None = None) -> tuple[str, str | None]:
    """(absolute patched, warning or None). The symlink is kept, not followed,
    so a `uv tool upgrade` is picked up; argv[0] is the fallback."""
    found = shutil.which("patched", path=path)
    program = os.path.abspath(found or sys.argv[0])
    warning = None
    if ".venv" in Path(program).parts:
        warning = f"{program} is inside a .venv: the agent will run that checkout, not an installed patched"
    return program, warning


def floor(env: Mapping[str, str]) -> list[str]:
    """Appended to the captured PATH, so an `on` from a stripped shell still sees uv, brew, npm."""
    home = env.get("HOME") or str(Path.home())
    prefix = mac.brew_prefix(env)
    return [f"{home}/.local/bin", f"{prefix}/bin", "/usr/local/bin", *LAUNCHD_PATH.split(":")]


def agent_path(user_path: str, env: Mapping[str, str]) -> str:
    """The user's PATH (absolute, existing, first of each), then the floor where absent."""
    out: list[str] = []
    for d in user_path.split(os.pathsep):
        if d and os.path.isabs(d) and os.path.isdir(d) and d not in out:
            out.append(d)
    out += [d for d in dict.fromkeys(floor(env)) if d not in out]
    return os.pathsep.join(out)


def environment(env: Mapping[str, str] | None = None) -> dict[str, str]:
    """The agent's EnvironmentVariables: PATH, plus each behaviour var that is SET."""
    env = os.environ if env is None else env
    out = {"PATH": agent_path(env.get("PATH", ""), env)}
    out.update({k: env[k] for k in CARRIED if k in env})
    return out


def missing_tools(path: str) -> list[str]:
    """collect.TOOLS that do not resolve on path: each is a source the scan reads as empty."""
    return [t for t in collect.TOOLS if not shutil.which(t, path=path)]


def textfile_dir(env: Mapping[str, str]) -> Path:
    return export.textfile_target(env=env)[0]


def render_plist(program: str, env: dict[str, str]) -> bytes:
    """The agent, as bytes: the same inputs give the same bytes, so `on` can compare."""
    log = str(log_path())
    return plistlib.dumps({
        "Label": LABEL,
        "ProgramArguments": [program, "scan", "--quiet"],
        "StartCalendarInterval": {"Minute": MINUTE},
        "RunAtLoad": True,
        "ProcessType": "Background",
        "StandardOutPath": log,
        "StandardErrorPath": log,
        "EnvironmentVariables": env,
    }, sort_keys=True)


def parse_print(text: str) -> dict[str, str]:
    """`launchctl print`'s top-level `key = value` lines (one tab deep). Nested
    blocks, such as an event trigger's `state = active`, are skipped."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        if not line.startswith("\t") or line.startswith("\t\t"):
            continue
        key, sep, value = line[1:].partition(" = ")
        if sep and value != "{":
            out.setdefault(key, value)
    return out


def write_atomic(path: Path, data: bytes) -> None:
    """Temp file in the same directory, then rename, as export.write_prom does."""
    tmp = path.parent / f".{path.name}.{os.getpid()}.tmp"
    tmp.write_bytes(data)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


# --- launchd ---

def service() -> dict[str, str] | None:
    """The loaded job's top-level print fields, or None when launchd has no such job."""
    rc, out = _launchctl(["print", target()])
    if rc == 0:
        return parse_print(out)
    if rc == GONE:
        return None
    raise ScheduleError(f"launchctl print exited {rc}: {out.strip()}")


def _bootstrap() -> None:
    rc, out = _launchctl(["bootstrap", target().rsplit("/", 1)[0], str(plist_path())])
    if rc != 0:
        raise ScheduleError(f"launchctl bootstrap exited {rc}: {out.strip()}")


def _bootout() -> None:
    rc, out = _launchctl(["bootout", target()])
    if rc != 0:
        raise ScheduleError(f"launchctl bootout exited {rc}: {out.strip()}; {plist_path()} left in place")


def _wait_gone(wait: float) -> None:
    """A bootstrap straight after bootout can fail (5: Input/output error) while
    the old job tears down: wait, bounded, until print says it is gone."""
    deadline = time.monotonic() + wait
    while service() is not None:
        if time.monotonic() >= deadline:
            raise ScheduleError(f"{LABEL} still loaded {wait:.0f} s after bootout; run `patched schedule on` again")
        time.sleep(POLL)


# --- the verbs ---

def on(dry_run: bool = False, env: Mapping[str, str] | None = None, wait: float = WAIT) -> dict:
    """Write and load the agent. A second `on` with nothing changed does nothing;
    a changed plist (binary, PATH, env) is written and the job reloaded."""
    env = os.environ if env is None else env
    program, warning = resolve_patched(env.get("PATH"))
    agent_env = environment(env)
    text = render_plist(program, agent_env)
    result = {"label": LABEL, "plist": str(plist_path()), "program": [program, "scan", "--quiet"],
              "log": str(log_path()), "env": agent_env, "missing": missing_tools(agent_env["PATH"]),
              "warnings": [warning] if warning else [], "text": text.decode(), "action": "dry-run"}
    tdir, named = export.textfile_target(env=env)
    if not tdir.is_dir():
        if named:  # a typo must not quietly turn the metrics off
            raise ScheduleError(f"textfile dir {tdir} does not exist: every hourly scan would fail. "
                                "Create it, or set PATCHED_TEXTFILE_DIR.")
        result["warnings"].append(f"no patched.prom will be written ({tdir} is missing); "
                                  "each scan still saves its record")
    if dry_run:
        return result
    loaded = service() is not None
    path = plist_path()
    if loaded and path.exists() and path.read_bytes() == text:
        return result | {"action": "already on"}
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    AGENTS_DIR.mkdir(parents=True, exist_ok=True)
    write_atomic(path, text)
    if loaded:
        _bootout()
        _wait_gone(wait)
    _bootstrap()
    return result | {"action": "reloaded" if loaded else "loaded"}


def off() -> dict:
    """Unload the agent and remove its plist. Nothing installed is fine: `already off`."""
    loaded = service() is not None
    path = plist_path()
    result = {"label": LABEL, "plist": str(path)}
    if not loaded and not path.exists():
        return result | {"action": "already off"}
    if loaded:
        _bootout()
    path.unlink(missing_ok=True)
    return result | {"action": "off"}


def last_scan() -> dict | None:
    """The newest scan record for this host: when, how long, which stages failed.
    It counts hand runs too: a record does not say who ran it."""
    records = sorted(SCANS_DIR.glob(f"{scanner.host()}-*.json"))
    if not records:
        return None
    path = records[-1]
    try:
        s = json.loads(path.read_text())
    except (OSError, ValueError) as e:
        return {"path": str(path), "error": str(e)}
    return {"path": str(path), "started": s.get("started"), "stamp": s.get("stamp"),
            "seconds": round(s["finished"] - s["started"], 1) if s.get("finished") and s.get("started") else None,
            "failed": sorted(k for k, ok in (s.get("stages") or {}).items() if not ok)}


def _tail(path: Path, size: int = 4096) -> str | None:
    try:
        with path.open("rb") as f:
            f.seek(max(0, path.stat().st_size - size))
            lines = f.read().decode(errors="replace").splitlines()
    except OSError:
        return None
    return next((x for x in reversed(lines) if x.strip()), None)


def status(env: Mapping[str, str] | None = None) -> dict:
    """Loaded or not (state, runs, last exit code), the plist and program, the
    log, the last scan record, patched.prom's mtime, and PATH-tool or env drift."""
    env = os.environ if env is None else env
    svc = service()
    path = plist_path()
    plist = {}
    if path.exists():
        try:
            plist = plistlib.loads(path.read_bytes())
        except (OSError, plistlib.InvalidFileException, ValueError):
            plist = {}
    agent_env = plist.get("EnvironmentVariables") or {}
    log = Path(plist.get("StandardOutPath") or log_path())
    if plist:  # the agent's own dir: its carried var, else the built-in default (not this shell's)
        prom = Path(agent_env.get("PATCHED_TEXTFILE_DIR") or export.DEFAULT_TEXTFILE_DIR) / "patched.prom"
    else:  # no agent: where a scan from this shell writes
        prom = textfile_dir(env) / "patched.prom"
    return {
        "label": LABEL,
        "loaded": svc is not None,
        "state": (svc or {}).get("state"),
        "runs": (svc or {}).get("runs"),
        "last_exit": (svc or {}).get("last exit code"),
        "plist": str(path),
        "installed": path.exists(),
        "program": plist.get("ProgramArguments"),
        "log": str(log),
        "log_size": log.stat().st_size if log.exists() else None,
        "log_last": _tail(log),
        "last_scan": last_scan(),
        "prom": str(prom),
        "prom_mtime": prom.stat().st_mtime if prom.exists() else None,
        "prom_dir_missing": not prom.parent.is_dir(),
        "missing": missing_tools(agent_env["PATH"]) if "PATH" in agent_env else [],
        "drift": {k: {"shell": env.get(k), "plist": agent_env.get(k)}
                  for k in CARRIED if plist and env.get(k) != agent_env.get(k)},
    }
