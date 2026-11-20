"""patched.prom for node_exporter's textfile collector, and the scan record.

The .prom is written to a temp file in the same directory, then renamed,
so node_exporter never reads half a file. Label sets stay bounded: a
series per advisory only for the advisories we are exposed to.
"""
from __future__ import annotations

import json
import os
import re
import time
from collections import Counter
from collections.abc import Mapping
from pathlib import Path

from . import brewpatch, cvss, mac, net, osv


def default_textfile_dir(env: Mapping[str, str] | None = None) -> Path:
    """node_exporter's textfile directory as Homebrew installs it, under Homebrew's prefix."""
    return mac.brew_prefix(env) / "var/lib/node_exporter/textfile_collector"


DEFAULT_TEXTFILE_DIR = default_textfile_dir()
TEXTFILE_DIR = Path(os.environ.get("PATCHED_TEXTFILE_DIR", str(DEFAULT_TEXTFILE_DIR)))


def textfile_target(option: str | None = None, env: Mapping[str, str] | None = None) -> tuple[Path, bool]:
    """Where patched.prom goes, and whether someone named that directory.

    Named (--textfile-dir, or PATCHED_TEXTFILE_DIR) and missing is an error:
    a typo must not quietly turn the metrics off. The default missing only
    means there is no node_exporter here: the scan still saves its record.
    """
    env = os.environ if env is None else env
    if option:
        return Path(option), True
    if env.get("PATCHED_TEXTFILE_DIR"):
        return Path(env["PATCHED_TEXTFILE_DIR"]), True
    return TEXTFILE_DIR, False

HELP = {
    "patched_scan_timestamp_seconds": "When the scan finished (unix seconds).",
    "patched_scan_duration_seconds": "How long the scan took.",
    "patched_scan_ok": "1 if this stage of the scan worked; 0 means its numbers are missing, not zero.",
    "patched_items": "Installed copies, by source: one per version, so an unused keg counts too (not products).",
    "patched_items_outdated": "Items whose updater says a newer version exists.",
    "patched_items_unused": "Installed copies not in use (old kegs beside the one the opt link points at): evict.",
    "patched_items_unallowed": "Products installed but NOT on the product allow list, by source. A dependency only pulled in by others rides with them, uncounted. None loaded: all of them.",
    "patched_items_unmatched": "Items OSV cannot speak for: no_key, empty (OSV holds nothing) or blind. Not clean.",
    "patched_exposed": "Advisories we are exposed to, counted per item and per copy: a CVE in three kegs counts 3. "
                       "patch: available (a release or update fixes it), commit (fixed upstream in a commit, "
                       "no release yet), none (no fix known). One brew already patched is not counted here.",
    "patched_brew_patched": "Advisories the installed brew formula already patched (a backported fix names the "
                            "advisory or its fix commit): NOT exposed, not in patched_exposed.",
    "patched_listening": "TCP listeners by bind: any, address, loopback, or served/funnel (loopback fronted by tailscale serve/funnel). This user's processes only.",
    "patched_listening_unallowed": "Listeners beyond loopback NOT on the services allow list (none loaded: all of them).",
    "patched_allowlist_loaded": "1 if this allow list was found and read; 0 means every entry reads as not allowed.",
    "patched_allowlist_errors": "Lines in this allow list that could not be read; each allows nothing.",
    "patched_exposed_listening": "Listeners whose program has an advisory in use, by bind and KEV. The fast path counts bind!=\"loopback\": served and funnel reach beyond this Mac.",
    "patched_protection": "1 on, 0 off: FileVault, SIP, Gatekeeper, the application firewall.",
    "patched_launchd_jobs": "launchd jobs on disk, by scope and whether they always run.",
    "patched_kev_entries": "Entries in the CISA KEV catalog used for this scan.",
    "patched_install_items": "Items (installed copies) with at least one advisory of this fix kind: release "
                             "(install a release: the call to action), commit (fixed upstream in a commit, no "
                             "release yet), brew (brew already patched), none (no fix known). An item with "
                             "advisories of two kinds counts in both. kev: any of them known exploited.",
    "patched_detail_series": "1 if this file carries the DETAIL series (names on, PATCHED_DETAIL_SERIES=1), "
                             "0 if counts only: an empty detail panel then means names off, not nothing to do.",
    # Detail, only with --detail: these name products, versions and processes.
    "patched_advisory_exposed": "DETAIL: 1 per advisory matched, per item and version. patched_by_brew=\"true\" "
                                "is listed but NOT exposed (the formula backported its fix); fix_commit is "
                                "upstream's fix commit (12 hex) or empty. fix: release, commit, brew or none "
                                "(brew wins: keyed on patched_by_brew, never on patch).",
    "patched_install": "DETAIL: per item and fix kind, the number of its advisories of that kind. fixed: for "
                       "fix=release the HIGHEST fixed version they need, so one install clears them all "
                       "(latest when the updater says outdated but OSV names no version), else empty. "
                       "severity: the worst of them; kev: any known exploited.",
    "patched_item_unused": "DETAIL: 1 per installed copy not in use.",
    "patched_unallowed_item": "DETAIL: 1 per product installed but not allowed; a dependency that rides is not named.",
    "patched_listener": "DETAIL: 1 per TCP listener: process, port, bind.",
}


def esc(v: object) -> str:
    return str(v).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def series(name: str, labels: dict, value: float) -> str:
    inner = ",".join(f'{k}="{esc(v)}"' for k, v in labels.items())
    num = int(value) if float(value).is_integer() else round(value, 3)
    return f"{name}{{{inner}}} {num}" if inner else f"{name} {num}"


def tf(b: bool) -> str:
    return "true" if b else "false"


# Named series map a host's weak points, and a Prometheus is often shared and
# read without auth. So counts only by default: a shared Prometheus never
# holds names; the names stay in the scan record (600).
DETAIL_SERIES = os.environ.get("PATCHED_DETAIL_SERIES") == "1"


# A zero is a claim (an unused count once held a stale 3 after it fell to 0,
# because a Counter writes no series for 0). Every count
# family writes its whole label grid, zeros included, but only when the stage
# that counts it worked: a failed stage stays missing, never a clean 0.
# Each source needs every stage it names. apps needs brew too: brew's casks
# say which apps are theirs, so with brew failed every cask's app would count
# as hand-installed, a wrong number rather than a missing one.
SOURCES = {"brew-formula": ("brew",), "brew-cask": ("brew",), "app": ("apps", "brew"),
           "uv-tool": ("uv",), "npm-global": ("npm",)}
BINDS = ("any", "address", "loopback", "served", "funnel")
SEVERITIES = ("critical", "high", "medium", "low", "unknown")
UNMATCHED = ("no_key", "empty", "blind")
TF = ("false", "true")
PATCHES = ("available", "commit", "none")
FIXES = ("release", "commit", "brew", "none")  # what to do about an advisory, as the board reads it


def patch_label(adv: dict, item: dict) -> str:
    """The fix, as the board reads it: a release version, available (the updater
    says outdated), commit (fixed upstream, no release yet) or none (no fix known)."""
    if adv.get("fixed"):
        return adv["fixed"]
    if item.get("outdated"):
        return "available"
    return "commit" if adv.get("fix_commits") else "none"


def fix_kind(adv: dict, item: dict) -> str:
    """One of FIXES. Brew first: a brew-patched advisory may carry patch="none"
    (CVE-2026-58050/58051 on libssh2), and it is never "no fix"."""
    if adv.get("patched_by_brew") == "true":
        return "brew"
    patch = patch_label(adv, item)
    return patch if patch in ("commit", "none") else "release"


def install_fixed(patches: list[str]) -> str:
    """The one version that clears every release-fixed advisory: the HIGHEST
    by osv.vkey; "latest" if any is only `available` (OSV names no version)."""
    if "available" in patches:
        return "latest"
    return max(patches, key=osv.vkey)


def render(scan: dict, detail: bool = DETAIL_SERIES) -> str:
    rows: dict[str, list[str]] = {k: [] for k in HELP}
    add = lambda n, lab, v: rows[n].append(series(n, lab, v))

    def counted(name: str, labels: tuple[str, ...], counts: Counter, grid: list[tuple]) -> None:
        """Every combination in grid, 0 if uncounted, plus any counted outside it."""
        for combo in sorted(set(grid) | set(counts)):
            add(name, dict(zip(labels, combo)), counts.get(combo, 0))

    done = scan["stages"]
    sources = [(s,) for s, needs in SOURCES.items() if all(done.get(n, False) for n in needs)]

    add("patched_scan_timestamp_seconds", {}, scan["finished"])
    add("patched_scan_duration_seconds", {}, scan["finished"] - scan["started"])
    for stage, ok in sorted(scan["stages"].items()):
        add("patched_scan_ok", {"stage": stage}, 1 if ok else 0)

    items = scan["items"]
    ok = {s for (s,) in sources}  # a source whose stages failed is missing, never counted
    by_source = lambda keep: Counter((i["source"],) for i in items if i["source"] in ok and keep(i))
    counted("patched_items", ("source",), by_source(lambda i: True), sources)
    counted("patched_items_outdated", ("source",), by_source(lambda i: i.get("outdated")), sources)
    counted("patched_items_unused", ("source",), by_source(lambda i: not i.get("in_use", True)), sources)
    if detail:
        for i in items:
            if not i.get("in_use", True):
                add("patched_item_unused", {"source": i["source"], "product": i["name"], "version": i["version"]}, 1)
    if scan["stages"].get("osv", False):
        unmatched = Counter((i["source"], i["status"]) for i in items
                            if i["source"] in ok and i.get("status") in ("no_key", "empty", "blind"))
        counted("patched_items_unmatched", ("source", "reason"), unmatched,
                [(src, why) for (src,) in sources for why in UNMATCHED])
        counts: Counter = Counter()
        brewed: Counter = Counter()
        # The rollup: per (item, fix kind) its advisories, so the board can say
        # what to install without ordering versions in PromQL (it cannot).
        install: dict[tuple, list[tuple[dict, str]]] = {}
        for n, i in enumerate(items):
            brew = i["source"] == "brew-formula"
            use = tf(i.get("in_use", True))
            for a in i.get("advisories", []):
                patch = patch_label(a, i)
                fix = fix_kind(a, i)
                commits = a.get("fix_commits") or []
                lab = {"advisory": a["advisory"], "product": i["name"], "version": i["version"],
                       "source": i["source"], "severity": a["severity"], "kev": tf(a["kev"]),
                       "patch": patch, "in_use": use,
                       "patched_by_brew": a.get("patched_by_brew") or ("unknown" if brew else "n/a"),
                       "fix_commit": min(commits)[:12] if commits else "", "fix": fix}
                if detail:
                    add("patched_advisory_exposed", lab, 1)
                install.setdefault((n, fix), []).append((a, patch))
                if not brewpatch.exposed(a):  # brew backported the fix: listed, never counted exposed
                    brewed[(a["severity"], tf(a["kev"]), use)] += 1
                    continue
                counts[(a["severity"], tf(a["kev"]), patch if patch in PATCHES else "available", use)] += 1
        counted("patched_exposed", ("severity", "kev", "patch", "in_use"), counts,
                [(sev, kev, patch, use) for sev in SEVERITIES for kev in TF
                 for patch in PATCHES for use in TF])
        brew_ok = done.get("brew_patches", False) and ("brew-formula",) in sources
        if brew_ok:  # failed: no count claims 0
            counted("patched_brew_patched", ("severity", "kev", "in_use"), brewed,
                    [(sev, kev, use) for sev in SEVERITIES for kev in TF for use in TF])
        fixes = [f for f in FIXES if f != "brew" or brew_ok]
        per_item: Counter = Counter()
        named: dict[tuple, list[tuple[dict, str]]] = {}  # two copies with one label set: one series
        for (n, fix), advs in install.items():
            i = items[n]
            use = tf(i.get("in_use", True))
            if fix in fixes:
                per_item[(fix, tf(any(a["kev"] for a, _ in advs)), use)] += 1
            named.setdefault((i["source"], i["name"], i["version"], use, fix), []).extend(advs)
        if detail:
            for (src, name, ver, use, fix), advs in sorted(named.items()):
                add("patched_install", {"source": src, "product": name, "version": ver, "in_use": use,
                                        "fix": fix,
                                        "fixed": install_fixed([p for _, p in advs]) if fix == "release" else "",
                                        "severity": cvss.worst(*(a["severity"] for a, _ in advs)),
                                        "kev": tf(any(a["kev"] for a, _ in advs))}, len(advs))
        counted("patched_install_items", ("fix", "kev", "in_use"), per_item,
                [(fix, kev, use) for fix in fixes for kev in TF for use in TF])
    else:  # OSV failed: say unknown, never zero
        for src, n in sorted(Counter(i["source"] for i in items if i["source"] in ok).items()):
            add("patched_items_unmatched", {"source": src, "reason": "error"}, n)

    if done.get("listeners", False):
        counted("patched_listening", ("bind",), Counter((li["bind"],) for li in scan["listeners"]),
                [(b,) for b in BINDS])
    allow = scan.get("allow", {}).get("services")
    add("patched_allowlist_loaded", {"list": "services"}, 1 if allow is not None else 0)
    add("patched_listening_unallowed", {}, sum(1 for li in scan["listeners"]
                                               if li["bind"] != "loopback" and not li.get("allowed")))
    if detail:
        for li in scan["listeners"]:
            add("patched_listener", {"process": li["process"], "port": li["port"], "bind": li["bind"]}, 1)
    products = scan.get("allow", {}).get("products")
    if done.get("products", False) and products:  # else the stage line says why, and no count claims 0
        unallowed = {s: names for s, names in products["unallowed"].items() if (s,) in sources}
        counted("patched_items_unallowed", ("source",),
                Counter({(s,): len(names) for s, names in unallowed.items() if names}), sources)
        add("patched_allowlist_loaded", {"list": "products"}, 1 if products["loaded"] else 0)
        add("patched_allowlist_errors", {"list": "products"}, len(products["errors"]))
        if detail:
            for s, names in sorted(unallowed.items()):
                for n in names:
                    add("patched_unallowed_item", {"source": s, "name": n}, 1)
    if scan["stages"].get("osv", False) and scan["stages"].get("link", False):
        counted("patched_exposed_listening", ("bind", "kev"),
                Counter((li["bind"], tf(li.get("kev", False))) for li in scan["listeners"] if li.get("exposed")),
                [(b, kev) for b in BINDS for kev in TF])
    for check, v in sorted(scan["protections"].items()):
        add("patched_protection", {"check": check}, v)
    if done.get("launchd", False):
        jobs = Counter((j["scope"], tf(j.get("always", False))) for j in scan["launchd"])
        counted("patched_launchd_jobs", ("scope", "always"), jobs,
                [(scope, a) for scope in sorted({sc for sc, _ in jobs}) for a in TF])
    if scan.get("kev"):
        add("patched_kev_entries", {"catalog": scan["kev"]["version"]}, scan["kev"]["count"])
    add("patched_detail_series", {}, 1 if detail else 0)
    # macOS version: not ours to export; node_exporter's node_os_info already carries it.

    out = []
    for name, lines in rows.items():
        if lines:
            out += [f"# HELP {name} {HELP[name]}", f"# TYPE {name} gauge", *lines]
    return "\n".join(out) + "\n"


def write_prom(text: str, directory: Path = TEXTFILE_DIR) -> Path:
    """Temp file in the same directory, then rename: never half a file."""
    path = directory / "patched.prom"
    tmp = directory / f".patched.prom.{os.getpid()}.tmp"
    tmp.write_text(text)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)
    return path


def write_record(scan: dict) -> Path:
    """~/.patched/scans/<host>-<time>.json, 600 in a 700 directory."""
    d = net.private_dir(net.HOME / "scans")
    net.private_dir(net.HOME)
    path = d / f"{scan['host']}-{scan['stamp']}.json"
    net.write_private(path, json.dumps(scan, indent=1, default=sorted))
    return path


KEEP_DAYS = 30
RECORD = re.compile(r"^(?P<host>.+)-(?P<stamp>\d{8}T\d{6})\.json$")  # write_record's name; a host may hold -


def keep_days(env: Mapping[str, str] | None = None) -> int:
    """$PATCHED_KEEP_DAYS, else 30; 0 keeps every record. ValueError unless a whole number of 0 or more."""
    env = os.environ if env is None else env
    raw = env.get("PATCHED_KEEP_DAYS", "").strip()
    if not raw:
        return KEEP_DAYS
    if not re.fullmatch(r"[0-9]+", raw):
        raise ValueError(f"PATCHED_KEEP_DAYS={raw!r} is not a whole number of 0 or more: no records pruned")
    return int(raw)


def record_time(path: Path) -> tuple[str, float] | None:
    """(host, local time) from a record's name, never its mtime; None if it is not a record."""
    m = RECORD.match(path.name)
    if not m or not path.is_file():
        return None
    try:
        return m["host"], time.mktime(time.strptime(m["stamp"], "%Y%m%dT%H%M%S"))
    except (ValueError, OverflowError):
        return None


def prune_records(directory: Path, days: int, now: float) -> list[Path]:
    """Remove the records in directory older than days; return them, oldest first.

    0 keeps every record. Each host's newest record stays whatever its age,
    so `patched report` always has one. Any other file is left alone.
    """
    if days <= 0 or not directory.is_dir():
        return []
    records = []
    for p in directory.iterdir():
        if found := record_time(p):
            host, t = found
            records.append((t, host, p))
    records.sort()
    newest = {host: p for _, host, p in records}  # sorted by time: the last one wins
    gone = [p for t, host, p in records if now - t > days * 86400 and newest[host] != p]
    for p in gone:
        p.unlink()
    return gone
