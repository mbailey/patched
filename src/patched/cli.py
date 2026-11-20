"""patched - what on this Mac needs patching. Help first: every verb is here."""
from __future__ import annotations

import json
import os
import sys
import time
from collections import Counter
from pathlib import Path
from typing import TextIO

import click
from click.core import ParameterSource

from . import allow as allowlist
from . import brewpatch, export, mac, report
from . import scan as scanner
from . import schedule as sched

CTX = {"help_option_names": ["-h", "--help"]}
QUIET = click.option("-q", "--quiet", is_flag=True, help="No progress lines on stderr.")


class StageLines:
    """Progress on stderr, one line per stage: `[ 3/13] apps 0.4 s`.

    On a terminal the line opens when the stage starts, so a slow one shows
    what it is waiting on; in a pipe or a log, only finished lines.
    """

    def __init__(self, names: list[str], stream: TextIO | None = None) -> None:
        self.names, self.stream = names, stream or sys.stderr
        self.tty = self.stream.isatty()

    def _head(self, name: str) -> str:
        n, w = len(self.names), len(str(len(self.names)))
        i = self.names.index(name) + 1 if name in self.names else 0
        return f"[{i:>{w}}/{n}] {name}"

    def start(self, name: str) -> None:
        if self.tty:
            click.echo(f"{self._head(name)} ...", file=self.stream, nl=False)

    def done(self, name: str, ok: bool, seconds: float) -> None:
        tail = f"{seconds:.1f} s" + ("" if ok else " FAILED")
        click.echo(f" {tail}" if self.tty else f"{self._head(name)} {tail}", file=self.stream)


@click.group(context_settings=CTX, invoke_without_command=True)
@click.pass_context
def main(ctx: click.Context) -> None:
    """patched - What on this Mac needs patching: inventory, OSV and KEV matches, node_exporter metrics"""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


def macos_only() -> None:
    """Off macOS, stop before any work: one plain line, exit 2."""
    if why := mac.off_macos():
        click.echo(why, err=True)
        raise SystemExit(2)


class TextfileDirMissing(click.ClickException):
    """A textfile directory someone named is missing: one line, exit 2, before the scan."""
    exit_code = 2


@main.command(context_settings=CTX)
@click.option("-n", "--dry-run", is_flag=True, help="Print patched.prom; write nothing.")
@click.option("--offline", is_flag=True, help="Collect only; no OSV, KEV or brew update (unmatched reads 'error').")
@click.option("--no-update", is_flag=True, help="Skip `brew update` (it refreshes brew's index; installs nothing).")
@click.option("--detail/--counts-only", default=export.DETAIL_SERIES, show_default=True,
              help="Add series that name advisories, products and listeners ($PATCHED_DETAIL_SERIES=1). "
                   "Counts only: a shared Prometheus never holds names.")
@click.option("--textfile-dir", type=click.Path(file_okay=False),
              default=str(export.TEXTFILE_DIR), show_default=True,
              help="node_exporter's textfile directory ($PATCHED_TEXTFILE_DIR). "
                   "Named and missing is an error; the default missing skips patched.prom.")
@click.option("-q", "--quiet", is_flag=True,
              help="No progress lines and no report: the summary and `wrote` lines only.")
def scan(dry_run: bool, offline: bool, no_update: bool, detail: bool, textfile_dir: str | None,
         quiet: bool) -> None:
    """Inventory, match, write patched.prom and the scan record (~/.patched/scans, 600).

    No node_exporter textfile directory at the default: the scan still runs
    and saves its record, and writes no patched.prom.
    """
    macos_only()
    if click.get_current_context().get_parameter_source("textfile_dir") is ParameterSource.DEFAULT:
        textfile_dir = None  # nobody named it: the default may be missing
    tdir, named = export.textfile_target(textfile_dir)
    if named and not dry_run and not tdir.is_dir():
        raise TextfileDirMissing(f"textfile directory {tdir} does not exist: create it, "
                                 "or name another (--textfile-dir, PATCHED_TEXTFILE_DIR)")
    network, update = not offline, not no_update
    progress = None if quiet else StageLines(scanner.plan(network=network, update=update))
    s = scanner.run(network=network, update=update, progress=progress)
    prom = export.render(s, detail=detail)
    bad = [k for k, ok in s["stages"].items() if not ok]
    if dry_run:
        click.echo(prom, nl=False)
        if bad:
            click.echo("FAILED stages: " + json.dumps({k: s["errors"][k] for k in bad}), err=True)
        return
    rec = export.write_record(s)
    path = export.write_prom(prom, tdir) if named or tdir.is_dir() else None
    if not quiet:
        click.echo(report.render(report.build(s, rec), color=_color()))
    click.echo(summary(s))
    if path is None:
        click.echo(f"wrote {rec}; no patched.prom (no node_exporter textfile directory at {tdir}; "
                   "set PATCHED_TEXTFILE_DIR to write one)")
    else:
        names = "names on" if detail else "counts only; --detail adds names"
        click.echo(f"wrote {path} ({len(prom.splitlines())} lines, {names}) and {rec}")
    try:
        days = export.keep_days()
    except ValueError as e:
        click.echo(str(e), err=True)
    else:
        if gone := export.prune_records(rec.parent, days, time.time()):
            click.echo(f"pruned {_plural(len(gone), 'record', 'records')} older than "
                       f"{_plural(days, 'day', 'days')}")
    if bad:
        click.echo(f"FAILED stages: {', '.join(bad)}: " + json.dumps({k: s['errors'][k] for k in bad}), err=True)
        raise SystemExit(1)


def _plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def summary(s: dict) -> str:
    """The one line a scan prints. A brew-patched advisory is not exposed: it is named apart."""
    st = Counter(i.get("status") for i in s["items"])
    advs = [a for i in s["items"] for a in i.get("advisories", [])]
    live = [a for a in advs if brewpatch.exposed(a)]
    kev = sum(a["kev"] for a in live)
    return (f"{len(s['items'])} items: {st['exposed']} exposed ({len(live)} advisories, {kev} known exploited), "
            f"{st['patched']} patched by brew ({len(advs) - len(live)} advisories brew-patched), "
            f"{st['clean']} clean, {st['no_key'] + st['empty'] + st['blind']} unmatched "
            f"(no_key {st['no_key']}, empty {st['empty']}, blind {st['blind']}); "
            f"{s['finished'] - s['started']:.1f} s")


def _color() -> bool:
    """Colour only on a terminal, and never with NO_COLOR set (no-color.org)."""
    return sys.stdout.isatty() and "NO_COLOR" not in os.environ


class RecordUnreadable(click.ClickException):
    """The newest scan record could not be read: one line naming it, exit 2."""
    exit_code = 2


@main.command("report", context_settings=CTX)
@click.option("--json", "as_json", is_flag=True, help="The rollup the text is rendered from, as JSON.")
def report_cmd(as_json: bool) -> None:
    """What to do, from the newest scan record of this host: no new scan.

    Grouped by the fix, most urgent first; Install now ends with the
    commands that do it. patched never runs them.
    """
    last = sched.last_scan()
    if last is None:
        click.echo("no scan yet: run patched scan", err=True)
        raise SystemExit(1)
    if "error" in last:
        raise RecordUnreadable(f"scan record {last['path']} unreadable: {last['error']}")
    try:
        s = json.loads(Path(last["path"]).read_text())
        rollup = report.build(s, last["path"])
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
        raise RecordUnreadable(f"scan record {last['path']} unreadable: {e!r}") from e
    if as_json:
        click.echo(json.dumps(rollup, indent=1))
    else:
        click.echo(report.render(rollup, color=_color()), nl=False)


@main.command(context_settings=CTX)
@click.option("--json", "as_json", is_flag=True, help="The items as JSON.")
@QUIET
def inventory(as_json: bool, quiet: bool) -> None:
    """Collect only: what is installed, by source. No network."""
    progress = None if quiet else StageLines(scanner.plan(network=False))
    s = scanner.run(network=False, progress=progress)
    if as_json:
        click.echo(json.dumps(s["items"], indent=1))
        return
    for src, n in sorted(Counter(i["source"] for i in s["items"]).items()):
        keyed = sum(1 for i in s["items"] if i["source"] == src and i.get("key"))
        click.echo(f"{src:14} {n:4}  ({keyed} with an OSV key)")


# --- the product allow list: show it, check this Mac, diff a Brewfile ---

def _at(e: dict, root: Path) -> str:
    """Where a line came from, relative to the config: `host/host1/Brewfile:3`."""
    path, _, n = e["where"].rpartition(":")
    p = Path(path)
    return f"{p.relative_to(root) if p.is_relative_to(root) else p}:{n}"


def _why(e: dict) -> str:
    return f"  # {e['why']}" if e.get("why") else ""


def _head(p: dict) -> str:
    if not p["loaded"]:
        return f"no product allow list: {p['config']} has no Brewfile or apps file; nothing is allowed"
    return f"config {p['config']}  host {p['host']}  class {p['class'] or '-'}  ({len(p['files'])} files)"


class ListError(click.ClickException):
    """The list could not be read at all: one line, exit 2, as `check` does."""
    exit_code = 2


def _products(host: str) -> dict:
    try:
        return allowlist.products(host)
    except (ValueError, FileNotFoundError) as e:  # a host or class that is not one segment; a dangling link
        raise ListError(str(e)) from None


def _errors(errors: list[str]) -> None:
    for e in errors:
        click.echo(f"unreadable: {e}", err=True)


@main.group(context_settings=CTX, invoke_without_command=True)
@click.option("--host", help="Another host's layers (default: this Mac).")
@click.option("--json", "as_json", is_flag=True, help="The merged list as JSON.")
@click.pass_context
def allow(ctx: click.Context, host: str | None, as_json: bool) -> None:
    """The product allow list: every line, merged from the fleet, class and
    host layers, with the file and line it came from. Exit 1 if a line can't
    be read (it allows nothing)."""
    ctx.obj = host or scanner.host()
    if ctx.invoked_subcommand is not None:
        return
    p = _products(ctx.obj)
    if as_json:
        click.echo(json.dumps(p, indent=1))
    else:
        click.echo(_head(p))
        root = Path(p["config"])
        for e in p["entries"]:
            click.echo(f"{_at(e, root):26} {allowlist.line(e)}{_why(e)}")
        layers = Counter(e["layer"] for e in p["entries"])
        click.echo(f"{len(p['entries'])} lines ({', '.join(f'{k} {n}' for k, n in layers.items()) or 'none'}); "
                   f"{len(p['errors'])} unreadable")
    _errors(p["errors"])
    if p["errors"]:
        raise SystemExit(1)


def _rides(parent: str, depth: int, children: dict[str, set[str]], seen: set[str]) -> None:
    for c in sorted(children.get(parent, ())):
        click.echo(f"{'  ' * depth}+ {c} (rides)")
        if c not in seen:
            seen.add(c)
            _rides(c, depth + 1, children, seen)


@allow.command(context_settings=CTX)
@click.option("--json", "as_json", is_flag=True, help="The match result as JSON.")
@QUIET
@click.pass_obj
def check(host: str, as_json: bool, quiet: bool) -> None:
    """What is installed on this Mac but not allowed, by source. A dependency
    that is not allowed rides under what pulled it in. Collect only: no
    network. Exit 1 if anything is not allowed, a line can't be read, or a
    collect stage failed (its products are missing, not allowed)."""
    if host != scanner.host():
        raise click.UsageError("check reads this Mac's inventory; --host is for the list and diff")
    progress = None if quiet else StageLines(scanner.plan(network=False, update=False))
    s = scanner.run(network=False, update=False, progress=progress)
    r = s["allow"]["products"]
    if r is None:
        click.echo(f"FAILED: products: {s['errors'].get('products')}", err=True)
        raise SystemExit(2)
    failed = [k for k in ("brew", "apps", "uv", "npm") if not s["stages"].get(k, False)]
    if as_json:
        click.echo(json.dumps(r, indent=1))
    else:
        if not r["loaded"]:
            click.echo(f"no product allow list in {allowlist.config_dir()}: nothing is allowed")
        versions: dict[tuple[str, str], list[str]] = {}
        children: dict[str, set[str]] = {}
        for i in s["items"]:
            versions.setdefault((i["source"], i["name"]), []).append(str(i.get("version") or ""))
            for parent in i.get("under") or ():
                children.setdefault(parent, set()).add(i["name"])
        for src in allowlist.PRODUCT_SOURCES:
            names = r["unallowed"][src]
            if names:
                click.echo(f"{src}: {len(names)} not allowed")
            for n in names:
                click.echo(f"  {n} {' '.join(sorted(set(versions.get((src, n), []))))}".rstrip())
                _rides(f"cask {n}" if src == "brew-cask" else n, 2, children, set())
        total = sum(len(v) for v in r["unallowed"].values())
        by = ", ".join(f"{k} {len(v)}" for k, v in r["unallowed"].items() if v)
        click.echo(f"{total} not allowed{f' ({by})' if by else ''}, {len(r['riding'])} riding with them; "
                   f"{len(r['files'])} list files, {len(r['errors'])} unreadable lines")
    _errors(r["errors"])
    if failed:
        click.echo(f"FAILED stages: {', '.join(failed)}: their products are missing, not allowed", err=True)
    if any(r["unallowed"].values()) or r["errors"] or failed:
        raise SystemExit(1)


@allow.command("diff", context_settings=CTX)
@click.argument("file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.pass_obj
def diff_(host: str, file: Path) -> None:
    """An install list (a Brewfile) against the allow list. `+` it installs
    and nothing allows; `?` a kind patched never scans (tap, go, cargo, ...);
    `-` allowed, but not in FILE. By name: aliases are not resolved. Exit 1
    on any `+`, or a line in FILE that can't be read."""
    p = _products(host)
    wanted, errors = allowlist.read_brewfile(file, str(file))
    d = allowlist.diff(wanted, p)
    root = Path(p["config"])
    if not p["loaded"]:
        click.echo(_head(p))
    for sign, key in (("+", "not_allowed"), ("?", "unchecked")):
        for e in d[key]:
            click.echo(f"{sign} {allowlist.line(e)}  ({e['where'].rpartition(':')[2]})")
    for e in d["lacking"]:
        click.echo(f"- {allowlist.line(e)}  ({_at(e, root)})")
    click.echo(f"{file}: {len(wanted)} lines: {len(d['not_allowed'])} not allowed, {len(d['unchecked'])} "
               f"not checked, {len(errors)} unreadable; the list has {len(d['lacking'])} lines it lacks")
    _errors(errors)
    if d["not_allowed"] or errors:
        raise SystemExit(1)


# --- patched schedule: an hourly scan as a user LaunchAgent ---

class ScheduleFailed(click.ClickException):
    """launchctl refused, or `on` would schedule a scan that cannot run: one line, exit 1."""
    exit_code = 1


def _when(ts: float | None) -> str:
    if ts is None:
        return "-"
    mins = max(0, int((time.time() - ts) // 60))
    ago = f"{mins} min ago" if mins < 120 else f"{mins // 60} h ago"
    return f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(ts))} ({ago})"


def _warn(r: dict) -> None:
    for w in r.get("warnings", []):
        click.echo(f"warning: {w}", err=True)
    if r.get("missing"):
        click.echo(f"warning: not on the agent's PATH: {', '.join(r['missing'])}: "
                   "those sources would read as empty", err=True)


@main.group(context_settings=CTX)
def schedule() -> None:
    """An hourly `patched scan` as a user LaunchAgent (~/Library/LaunchAgents, no sudo).

    Nothing is scheduled until you run `patched schedule on`. The agent runs
    only while you are logged in; a scan missed in sleep runs on wake.
    """


@schedule.command("on", context_settings=CTX)
@click.option("-n", "--dry-run", is_flag=True, help="Print the plist; write nothing, load nothing.")
def schedule_on(dry_run: bool) -> None:
    """Write and load the agent: `patched scan --quiet` hourly at :07, and at load.

    It runs the `patched` on your PATH, with your PATH (plus a floor) and the
    PATCHED_* / HOMEBREW_PREFIX vars set now. Change them? Run `on` again.
    A second `on` with nothing changed does nothing.
    """
    macos_only()
    try:
        r = sched.on(dry_run=dry_run)
    except sched.ScheduleError as e:
        raise ScheduleFailed(str(e)) from e
    if dry_run:
        click.echo(r["text"], nl=False)
        click.echo(f"dry run: would write {r['plist']} and load {r['label']}; nothing written, nothing loaded",
                   err=True)
    else:
        click.echo(f"{r['action']}: {r['label']} ({r['plist']})")
        click.echo(f"runs: {' '.join(r['program'])}, hourly at :{sched.MINUTE:02d} and at load")
        click.echo(f"log: {r['log']}")
    _warn(r)


@schedule.command("off", context_settings=CTX)
def schedule_off() -> None:
    """Unload the agent and remove its plist. Nothing installed: `already off`, exit 0."""
    try:
        r = sched.off()
    except sched.ScheduleError as e:
        raise ScheduleFailed(str(e)) from e
    click.echo(f"{r['action']}: {r['label']} ({r['plist']})")


@schedule.command("status", context_settings=CTX)
def schedule_status() -> None:
    """Loaded or not, last run, last exit code, the log; and PATH or env drift."""
    try:
        s = sched.status()
    except sched.ScheduleError as e:
        raise ScheduleFailed(str(e)) from e
    if s["loaded"]:
        click.echo(f"{s['label']}: loaded (state {s['state'] or '-'}, runs {s['runs'] or '-'}, "
                   f"last exit code {s['last_exit'] or '-'})")
    else:
        click.echo(f"{s['label']}: not loaded")
    click.echo(f"plist: {s['plist']} ({'installed' if s['installed'] else 'not installed'})")
    if s["program"]:
        click.echo(f"program: {' '.join(s['program'])}")
    if s["log_size"] is None:
        click.echo(f"log: {s['log']} (none yet)")
    else:
        click.echo(f"log: {s['log']} ({s['log_size']} bytes)")
        if s["log_last"]:
            click.echo(f"  last line: {s['log_last']}")
    last = s["last_scan"]
    if last is None:
        click.echo("last run: none (no scan record for this host)")
    elif "error" in last:
        click.echo(f"last run: {last['path']} unreadable: {last['error']}")
    else:
        failed = f"; failed: {', '.join(last['failed'])}" if last["failed"] else ""
        secs = f"{last['seconds']} s" if last["seconds"] is not None else "-"
        click.echo(f"last run: {_when(last['started'])}, {secs}{failed} (any scan, by hand or the agent)")
    if s["prom_dir_missing"]:
        click.echo(f"patched.prom: none ({Path(s['prom']).parent} is missing)")
    else:
        click.echo(f"patched.prom: {_when(s['prom_mtime'])} ({s['prom']})")
    if s["missing"]:
        click.echo(f"warning: not on the agent's PATH: {', '.join(s['missing'])}", err=True)
    for k, v in s["drift"].items():
        click.echo(f"warning: {k} is {v['shell']!r} in this shell, {v['plist']!r} in the agent: "
                   "run `patched schedule on` to carry it", err=True)


def _completion_dir() -> Path:
    """Where bash-completion 2 looks for a user's completions on first TAB:
    $BASH_COMPLETION_USER_DIR/completions, else
    ${XDG_DATA_HOME:-~/.local/share}/bash-completion/completions."""
    base = os.environ.get("BASH_COMPLETION_USER_DIR")
    if not base:
        data = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
        base = str(Path(data) / "bash-completion")
    return Path(base) / "completions"


@main.command(context_settings=CTX)
@click.argument("shell", type=click.Choice(["bash", "zsh", "fish"]), default="bash")
@click.option("--install", is_flag=True,
              help="Write the bash script where bash-completion 2 finds it on the next TAB.")
def completions(shell: str, install: bool) -> None:
    """Print the TAB-completion script for SHELL (default bash): every verb and option.

    Try it in this shell: `eval "$(patched completions)"`. Keep it:
    `patched completions --install` writes
    ~/.local/share/bash-completion/completions/patched (or under
    $BASH_COMPLETION_USER_DIR), which bash-completion 2 loads on first TAB.
    """
    from click.shell_completion import get_completion_class

    cls = get_completion_class(shell)
    if cls is None:  # click knows these three; a new click might drop one
        raise click.ClickException(f"click has no {shell} completion")
    source = cls(main, {}, "patched", "_PATCHED_COMPLETE").source()
    if not install:
        click.echo(source, nl=False)
        return
    if shell != "bash":
        raise click.ClickException(f"--install is bash only for now; for {shell}, print it and place it yourself")
    path = _completion_dir() / "patched"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source if source.endswith("\n") else source + "\n", encoding="utf-8")
    click.echo(f"wrote {path}; a new TAB on `patched` in any bash picks it up")
