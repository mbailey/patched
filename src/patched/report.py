"""The report: what to do about a scan, grouped by the fix, most urgent first.

A list of advisories is not an answer. The answer is grouped by what to do,
and Install now ends with the commands that do it. patched never runs them:
it reads only.

`build(scan)` is pure: a scan record in, the rollup out (what `report --json`
prints). `render(rollup)` turns the rollup into 80-column plain text, so the
text and the JSON can never disagree.
"""
from __future__ import annotations

import re
import textwrap
import time
from collections.abc import Callable
from pathlib import Path

from . import cvss, export

WIDTH = 80
# export.FIXES, in the order a reader acts on them: install, wait, decide, nothing.
GROUPS = (
    ("release", "Install now", ""),
    ("commit", "Wait for a release", "fixed upstream, not released yet"),
    ("none", "No fix known", "keep it only if you need it"),
    ("brew", "Already patched by Homebrew", "nothing to do"),
)
assert {fix for fix, _, _ in GROUPS} == set(export.FIXES)
SOURCE_NAMES = {"brew-cask": "cask", "uv-tool": "uv tool", "npm-global": "npm", "app": "app"}
SHOWN_SEVERITIES = ("critical", "high")
UNCHECKED = ("no_key", "empty", "blind")


# --- build: the rollup, pure ---

BINDS = {  # where a stranger can reach the program, in plain words
    "any": "*:{port}",
    "address": "{port} on one address",
    "served": "{port} via tailscale serve (tailnet)",
    "funnel": "{port} via tailscale funnel (internet)",
}


def _bind(li: dict) -> str:
    """Where a listener beyond loopback is reachable, in plain words: `*:8080`
    (every address), `8080 on one address`, `443 via tailscale serve
    (tailnet)`, `443 via tailscale funnel (internet)`. A kind it does not
    know reads `BIND:PORT`. The text and `report --json` both carry it."""
    form = BINDS.get(li["bind"])
    return form.format(port=li["port"]) if form else f"{li['bind']}:{li['port']}"


def _listening(scan: dict) -> dict[tuple, list[str]]:
    """(source, name, version) -> the binds beyond loopback of the listeners it runs."""
    out: dict[tuple, list[str]] = {}
    for li in scan.get("listeners") or []:
        if li.get("bind") == "loopback":
            continue
        for src, name, ver in li.get("items") or []:
            binds = out.setdefault((src, name, ver), [])
            if _bind(li) not in binds:
                binds.append(_bind(li))
    return out


def _row(item: dict, fix: str, advs: list[tuple[dict, str]], listening: list[str]) -> dict:
    worst = cvss.worst(*(a.get("severity", "unknown") for a, _ in advs))
    return {
        "source": item["source"], "name": item["name"], "version": item.get("version", ""),
        "in_use": item.get("in_use", True),
        "fixed": export.install_fixed([p for _, p in advs]) if fix == "release" else None,
        "advisories": len(advs),
        "severity": worst, "severity_count": sum(1 for a, _ in advs if a.get("severity") == worst),
        "kev": any(a.get("kev") for a, _ in advs),
        "listening": listening,
    }


def _order(row: dict) -> tuple:
    """Known exploited, then listening, then worst severity, then advisory count, then name."""
    return (not row["kev"], not row["listening"], -cvss.ORDER.index(row["severity"]),
            -row["advisories"], row["name"], row["source"], row["version"])


def commands(rows: list[dict]) -> list[str]:
    """One line per package manager, every row on it; uv takes one name, so one line each."""
    by = lambda src: sorted({r["name"] for r in rows if r["source"] == src})
    out = []
    if formulae := by("brew-formula"):
        out.append("brew upgrade " + " ".join(formulae))
    if casks := by("brew-cask"):
        out.append("brew upgrade --cask " + " ".join(casks))
    out += [f"uv tool upgrade {n}" for n in by("uv-tool")]
    if npms := by("npm-global"):
        out.append("npm install -g " + " ".join(f"{n}@latest" for n in npms))
    return out


def coverage(scan: dict) -> dict:
    items = scan.get("items") or []
    status = [i.get("status") for i in items]
    out = {"items": len(items), "checked": sum(1 for s in status if s in ("exposed", "patched", "clean"))}
    out |= {s: status.count(s) for s in UNCHECKED}
    return out


def build(scan: dict, record: str | Path | None = None) -> dict:
    """The rollup a report is rendered from. No I/O."""
    stages = scan.get("stages") or {}
    checked = bool(stages.get("osv"))
    rollup = {
        "host": scan.get("host"), "record": str(record) if record else None,
        "started": scan.get("started"), "finished": scan.get("finished"),
        "checked": checked,
        "reason": None if checked else (scan.get("errors") or {}).get("osv") or "the osv stage did not run",
        "groups": [], "coverage": coverage(scan),
    }
    if not checked:
        return rollup
    listening = _listening(scan)
    merged: dict[tuple, tuple[dict, list[tuple[dict, str]]]] = {}  # two copies of one item: one row
    for item in scan.get("items") or []:
        key = (item["source"], item["name"], item.get("version", ""))
        for a in item.get("advisories") or []:
            fix = export.fix_kind(a, item)
            merged.setdefault((fix, *key, item.get("in_use", True)), (item, []))[1].append(
                (a, export.patch_label(a, item)))
    for fix, title, note in GROUPS:
        rows = sorted((_row(item, fix, advs, listening.get(k[1:4], []))
                       for k, (item, advs) in merged.items() if k[0] == fix), key=_order)
        group = {"fix": fix, "title": title, "note": note, "rows": rows}
        if fix == "release":
            group["commands"] = commands(rows)
        rollup["groups"].append(group)
    return rollup


# --- render: 80-column text ---

def _plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def when(ts: float, now: float) -> str:
    """`today 14:23 (2 min ago)`: the record's local time and its age."""
    t, today = time.localtime(ts), time.localtime(now)
    yesterday = time.localtime(now - 86400)
    day = ("today" if t[:3] == today[:3] else "yesterday" if t[:3] == yesterday[:3]
           else time.strftime("%Y-%m-%d", t))
    mins = max(0, int((now - ts) // 60))
    ago = ("just now" if mins < 1 else f"{mins} min ago" if mins < 120
           else f"{mins // 60} h ago" if mins < 48 * 60 else f"{mins // 1440} days ago")
    return f"{day} {time.strftime('%H:%M', t)} ({ago})"


def _home(path: str) -> str:
    home = str(Path.home())
    return "~" + path[len(home):] if path == home or path.startswith(home + "/") else path


def _flags(row: dict) -> list[str]:
    out = []
    if row["kev"]:
        out.append("KNOWN EXPLOITED")
    if row["listening"]:
        out.append("listening on " + ", ".join(row["listening"]))
    if not row["in_use"]:
        out.append("(not in use)")
    if row["source"] != "brew-formula":
        out.append(f"({SOURCE_NAMES.get(row['source'], row['source'])})")
    return out


def _split(flag: str, width: int) -> list[str]:
    """A flag longer than width, broken after its commas: `listening on A, B, C`."""
    if len(flag) <= width:
        return [flag]
    parts, cur = [], ""
    for word in flag.split(", "):
        if cur and len(cur) + 2 + len(word) + 1 > width:
            parts.append(cur + ",")
            cur = word
        else:
            cur = f"{cur}, {word}" if cur else word
    return parts + [cur]


def _wrap_words(words: list[str], indent: str, sep: str = " ", tail: str = "") -> list[str]:
    """Words greedily onto lines of at most WIDTH; every line but the last ends in tail."""
    lines, cur = [], indent
    for w in words:
        if cur.strip() and len(cur) + len(sep) + len(w) + len(tail) > WIDTH:
            lines.append(cur + tail)
            cur = indent + "  " + w
        else:
            cur = cur + (sep if cur.strip() else "") + w
    return lines + [cur]


def render(rollup: dict, color: bool = False, now: float | None = None) -> str:
    now = time.time() if now is None else now
    paint: Callable[[str, str], str] = (lambda s, code: f"\033[{code}m{s}\033[0m") if color else (lambda s, _: s)

    def header(title: str, note: str, n: int) -> str:
        left = title + (f"  -  {note}" if note else "")
        gap = " " * max(2, 61 - len(left))
        return paint(title, "1") + (f"  -  {paint(note, '2')}" if note else "") + gap + _plural(n, "item", "items")

    out = [f"patched  {rollup['host'] or '-'}  scanned "
           + (when(rollup["started"], now) if rollup.get("started") else "at an unknown time"), ""]
    if not rollup["checked"]:
        out += textwrap.wrap(f"Advisories were not checked ({rollup['reason']}). Nothing below is a verdict.",
                             WIDTH - 2) + [""]
    else:
        rows = [r for g in rollup["groups"] for r in g["rows"]]
        ver = lambda r: f"{r['version']} -> {r['fixed']}" if r["fixed"] else r["version"]
        nw = max([11, *(len(r["name"]) for r in rows)])
        vw = max([17, *(len(ver(r)) for r in rows)])
        cw = max([2, *(len(str(r["advisories"])) for r in rows)])
        for g in rollup["groups"]:
            if not g["rows"] and g["fix"] != "release":
                continue
            if not g["rows"]:
                out += ["Nothing to install now.", ""]
                continue
            out.append(header(g["title"], g["note"], len(g["rows"])))
            for r in g["rows"]:
                first = (f"  {r['name']:<{nw}}  {ver(r):<{vw}}  {r['advisories']:>{cw}} "
                         f"{'advisory' if r['advisories'] == 1 else 'advisories':<10}")
                if r["severity"] in SHOWN_SEVERITIES:
                    sev = f"{r['severity_count']} {r['severity']}"
                    first += "  " + (paint(sev, "31") if r["severity"] == "critical" else sev)
                flags = _flags(r)
                shown = [paint(f, "31") if f == "KNOWN EXPLOITED" else f for f in flags]
                if flags and len(re.sub(r"\033\[[0-9;]*m", "", first)) + 2 + len("  ".join(flags)) <= WIDTH:
                    out.append(first + "  " + "  ".join(shown))  # the padding keeps the flags in column
                    continue
                out.append(first.rstrip())
                line, plain = "    ", "    "
                pairs = [(piece, piece) if f == s else (f, s)  # a flag too long alone breaks at its commas
                         for f, s in zip(flags, shown) for piece in (_split(f, WIDTH - 4) if f == s else [f])]
                for f, s in pairs:
                    if plain.strip() and len(plain) + 2 + len(f) > WIDTH:
                        out.append(line)
                        line, plain = "    ", "    "
                    line += ("  " if plain.strip() else "") + s
                    plain += ("  " if plain.strip() else "") + f
                if plain.strip():
                    out.append(line)
            if g.get("commands"):
                out.append("")
                for c in g["commands"]:
                    out += _wrap_words(c.split(" "), "  ", tail=" \\")
            out.append("")
    c = rollup["coverage"]
    other = c["items"] - c["checked"]
    text = f"Checked {c['checked']} of {_plural(c['items'], 'item', 'items')}."
    if rollup["checked"] and other:
        rest = other - c["no_key"] - c["empty"] - c["blind"]
        parts = [f"{c['no_key']} {'has' if c['no_key'] == 1 else 'have'} no key "
                 "(casks and apps are listed, never matched)" if c["no_key"] else "",
                 f"{c['empty']} {'is' if c['empty'] == 1 else 'are'} unknown to OSV" if c["empty"] else "",
                 f"{c['blind']} could not be matched by version" if c["blind"] else "",
                 f"{rest} {'was' if rest == 1 else 'were'} not matched" if rest > 0 else ""]
        text += f" No advisory source for the other {other}: " + ", ".join(p for p in parts if p) + "."
    out += textwrap.wrap(text, WIDTH - 2)
    if rollup.get("record"):
        out.append(f"Record: {_home(rollup['record'])}")
    return "\n".join(out) + "\n"
