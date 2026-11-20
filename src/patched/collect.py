"""Collectors: read-only, no sudo. Each returns plain dicts.

An item is one installed thing at one version. `key` is how OSV can know
it: [ecosystem, name, version], with the version from the key's own
ecosystem: brew formulae go by GIT repo and tag, uv tools by
PyPI, npm globals by npm. No key means no_key, never clean.
"""
from __future__ import annotations

import json
import os
import plistlib
import re
import shutil
import subprocess
import tomllib
import urllib.parse
from pathlib import Path

from . import brewpatch, mac

BREW = mac.brew_prefix()
# Every command `run` (and brew_update) calls by name. Under a PATH without one,
# `run` reads its source as empty with exit 0, so `patched schedule` checks the
# agent's PATH against this; tests/test_schedule.py fails if a new one is missing.
TOOLS = ("brew", "uv", "git", "npm", "tailscale", "lsof", "ps", "sw_vers", "fdesetup", "csrutil", "spctl")
GITHUB = re.compile(r"https://github\.com/([^/#?]+)/([^/#?]+)")
INTERPRETERS = re.compile(r"^(python[\d.]*|Python|node|ruby|perl|bun|deno)$")


def run(cmd: list[str], timeout: float = 120) -> str:
    """stdout of cmd; '' if it is missing or fails. stderr is dropped."""
    if not shutil.which(cmd[0]) and not Path(cmd[0]).exists():
        return ""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return p.stdout


def item(source: str, name: str, version: str | None, key: list | None = None, **extra) -> dict:
    return {"source": source, "name": name, "version": version, "key": key,
            "in_use": True, "outdated": False, **extra}


def github_repo(urls: list[str | None]) -> str | None:
    for u in urls:
        m = GITHUB.match(u or "")
        if m:
            return f"https://github.com/{m.group(1)}/{m.group(2).removesuffix('.git')}"
    return None


def strip_revision(version: str) -> str:
    """Brew's 1.11.1_7 is upstream 1.11.1, rebuilt (maybe patched) 7 times."""
    return re.sub(r"_\d+$", "", version)


def brew_update() -> None:
    """Refresh brew's own index so `outdated` is true; installs nothing."""
    if not shutil.which("brew"):
        raise RuntimeError("brew not found")
    p = subprocess.run(["brew", "update", "--quiet"], capture_output=True, text=True, timeout=600, check=False)
    if p.returncode != 0:
        raise RuntimeError(f"brew update exited {p.returncode}: {p.stderr.strip()[-200:]}")


def brew(info: dict | None = None) -> tuple[list[dict], set[str]]:
    """Formulae (every keg) and casks; also the app bundles casks put down."""
    if info is None:
        out = run(["brew", "info", "--json=v2", "--installed"])
        info = json.loads(out) if out else {"formulae": [], "casks": []}
    items, cask_apps = [], set()
    for f in info.get("formulae", []):
        urls = f.get("urls") or {}
        repo = github_repo([(urls.get("stable") or {}).get("url"),
                            (urls.get("head") or {}).get("url"), f.get("homepage")])
        opt = BREW / "opt" / f["name"]
        current = opt.resolve().name if opt.is_symlink() else None
        for inst in f.get("installed", []):
            v = inst["version"]
            in_use = current is None or v == current
            items.append(item(
                "brew-formula", f["name"], v,
                ["GIT", repo, strip_revision(v)] if repo else None,
                path=f"{BREW}/Cellar/{f['name']}/{v}/", ids={"brew": f["name"], "git": repo},
                in_use=in_use, outdated=bool(f.get("outdated")) and in_use,
                revision=v != strip_revision(v), tap=f.get("tap"),
                deprecated=bool(f.get("deprecated") or f.get("disabled")),
                keg_only=bool(f.get("keg_only")), updater="brew", **formula_facts(f)))
    for c in info.get("casks", []):
        apps = [a for art in c.get("artifacts", []) if isinstance(art, dict)
                for a in art.get("app", []) if isinstance(a, str)]
        cask_apps.update(Path(a).name for a in apps)
        items.append(item("brew-cask", c["token"], c.get("installed") or c.get("version"),
                          outdated=bool(c.get("outdated")), apps=apps, ids={"cask": c["token"]},
                          paths=[f"/Applications/{Path(a).name}/" for a in apps],
                          updater="self" if c.get("auto_updates") else "brew",
                          full_name=c.get("full_token") or c["token"], aliases=list(c.get("old_tokens") or []),
                          formula_deps=[d.rsplit("/", 1)[-1] for d in (c.get("depends_on") or {}).get("formula") or []]))
    return items, cask_apps


def formula_facts(f: dict) -> dict:
    """What the allow list needs to know (Homebrew's keep rule): asked for or
    pulled in, the formulae it needs at run time, and its other names."""
    installed = f.get("installed") or []
    return {"full_name": f.get("full_name") or f["name"],
            "on_request": any(i.get("installed_on_request") for i in installed),
            "deps": sorted({d["full_name"].rsplit("/", 1)[-1] for i in installed
                            for d in i.get("runtime_dependencies") or [] if d.get("full_name")}),
            "aliases": sorted(set(f.get("aliases") or []) | set(f.get("oldnames") or [])
                              | ({f["oldname"]} if f.get("oldname") else set()))}


def apps(skip: set[str], roots: tuple[Path, ...] = (Path("/Applications"), Path.home() / "Applications")) -> list[dict]:
    """App bundles a cask did not install. OSV holds none of them: no_key."""
    items = []
    for root in roots:
        for app in sorted(root.glob("*.app")):
            if app.name in skip:
                continue
            try:
                with open(app / "Contents" / "Info.plist", "rb") as fh:
                    pl = plistlib.load(fh)
            except Exception:  # noqa: BLE001 - plistlib also raises expat's errors
                pl = {"unreadable": True}  # still counted: an app we can't read is a blind spot
            mas = (app / "Contents" / "_MASReceipt").exists()
            items.append(item(
                "app", app.stem, path=f"{app}/", ids={"bundle_id": pl.get("CFBundleIdentifier")},
                version=str(pl.get("CFBundleShortVersionString") or pl.get("CFBundleVersion") or ""),
                updater="appstore" if mas else ("sparkle" if pl.get("SUFeedURL") else "unknown")))
    return items


def uv_tools(listing: str | None = None, tool_dir: Path | None = None) -> list[dict]:
    """uv tools by PyPI name; a tool installed from a path or git is local: no_key."""
    if listing is None:
        listing = run(["uv", "tool", "list"])
    if tool_dir is None:
        tool_dir = Path(run(["uv", "tool", "dir"]).strip() or Path.home() / ".local/share/uv/tools")
    items = []
    for line in listing.splitlines():
        m = re.match(r"^([^-\s]\S*) v(\d\S*)", line)
        if not m:
            continue
        name, ver = m.groups()
        receipt = tool_dir / name / "uv-receipt.toml"
        text = receipt.read_text() if receipt.exists() else ""
        local = uv_local(name, text)
        origin, built_from = uv_origin(name, text) if local else (None, None)
        items.append(item("uv-tool", name, ver, None if local else ["PyPI", name, ver],
                          local=local, updater="uv", path=f"{tool_dir}/{name}/",
                          ids={"pypi": None if local else name}, origin=origin, built_from=built_from))
    return items


LOCAL_KEYS = ("editable", "directory", "path", "git", "url")


def uv_local(name: str, receipt: str) -> bool:
    """Is the tool itself from a path, git or a URL? Only its own requirement counts:
    a tool that pins an extra by URL, yet comes from PyPI (it read local before)."""
    try:
        reqs = tomllib.loads(receipt).get("tool", {}).get("requirements", [])
    except tomllib.TOMLDecodeError:
        reqs = None
    if reqs is None:  # unreadable: the old test over the requirements text
        head = receipt.split("entrypoints", 1)[0]  # install-path below is not a source
        return bool(re.search(r"[{,]\s*(editable|directory|path|git|url)\s*=", head))
    mine = [r for r in reqs if isinstance(r, dict) and r.get("name") == name]
    return any(k in r for r in mine for k in LOCAL_KEYS) if mine else any(
        k in r for r in reqs if isinstance(r, dict) for k in LOCAL_KEYS)


def uv_origin(name: str, receipt: str) -> tuple[str | None, str | None]:
    """(origin, built_from) of a uv tool installed from git or a local checkout.

    origin is the git URL: the receipt's own for a git install, else the
    checkout's `origin` remote. None when there is none: a directory that is
    gone, or not a git repo, can't be named by a source.
    """
    try:
        reqs = tomllib.loads(receipt).get("tool", {}).get("requirements", [])
    except tomllib.TOMLDecodeError:
        return None, None
    local = [r for r in reqs if isinstance(r, dict) and any(k in r for k in ("git", "editable", "directory", "path"))]
    mine = [r for r in local if r.get("name") == name] or local[:1]
    if not mine:
        return None, None
    r = mine[0]
    if r.get("git"):
        return r["git"], None
    d = r.get("editable") or r.get("directory") or r.get("path")
    if not d or not Path(d).is_dir():
        return None, d
    return run(["git", "-C", d, "remote", "get-url", "origin"]).strip() or None, d


def npm_globals(out: str | None = None) -> list[dict]:
    if out is None:
        out = run(["npm", "ls", "-g", "--json", "--depth=0"])
    try:
        deps = json.loads(out or "{}").get("dependencies", {})
    except ValueError:
        deps = {}
    return [item("npm-global", n, d.get("version"), ["npm", n, d.get("version")], updater="npm",
                 path=f"{BREW}/lib/node_modules/{n}/", ids={"npm": n})
            for n, d in sorted(deps.items()) if d.get("version")]


def launchd() -> list[dict]:
    """Jobs on disk: label, program, whether they always run. Record only."""
    jobs = []
    for scope, d in (("user", Path.home() / "Library/LaunchAgents"),
                     ("agents", Path("/Library/LaunchAgents")),
                     ("daemons", Path("/Library/LaunchDaemons"))):
        for p in sorted(d.glob("*.plist")):
            try:
                with open(p, "rb") as fh:
                    pl = plistlib.load(fh)
            except Exception:  # noqa: BLE001 - plistlib also raises expat's errors
                jobs.append({"scope": scope, "path": str(p), "label": None, "unreadable": True})
                continue
            prog = pl.get("Program") or (pl.get("ProgramArguments") or [None])[0]
            jobs.append({"scope": scope, "path": str(p), "label": pl.get("Label"), "program": prog,
                         "always": bool(pl.get("RunAtLoad") or pl.get("KeepAlive")),
                         "disabled": bool(pl.get("Disabled"))})
    return jobs


def bind_of(host: str) -> str:
    if host in ("*", "0.0.0.0", "[::]", "::"):
        return "any"
    if host.startswith("127.") or host in ("[::1]", "::1", "localhost"):
        return "loopback"
    return "address"


def process_name(command: str, args: str) -> str:
    """lsof's command, or the script an interpreter runs (webapp.py -> webapp)."""
    if not INTERPRETERS.match(command):
        return command
    parts = args.split()[1:]
    i = 0
    while i < len(parts):
        a = parts[i]
        if a == "-m" and i + 1 < len(parts):
            return parts[i + 1]
        if not a.startswith("-"):
            return re.sub(r"\.(py|js|mjs|rb|pl)$", "", Path(a).name)
        i += 1
    return command


def listeners(out: str | None = None) -> list[dict]:
    """TCP listeners, one per process, port and bind. This user's processes only."""
    if out is None:
        out = run(["lsof", "+c", "0", "-nP", "-iTCP", "-sTCP:LISTEN", "-F", "pcn"])
    rows, pid, cmd, seen = {}, None, None, {}
    for line in out.splitlines():
        tag, val = line[:1], line[1:]
        if tag == "p":
            pid = val
        elif tag == "c":
            cmd = val
        elif tag == "n" and pid and cmd:
            host, _, port = val.rpartition(":")
            if pid not in seen:
                seen[pid] = (run(["ps", "-o", "comm=", "-p", pid]).strip(), run(["ps", "-o", "args=", "-p", pid]).strip())
            comm, args = seen[pid]
            proc = process_name(cmd, args)
            k = (proc, port, bind_of(host))
            r = rows.setdefault(k, {"process": proc, "port": port, "bind": k[2], "pids": set(), "paths": set()})
            r["pids"].add(pid)
            r["paths"].update(program_paths(comm, args))
    return [dict(r, pids=sorted(r["pids"]), paths=sorted(r["paths"]))
            for r in sorted(rows.values(), key=lambda r: (r["process"], r["port"]))]


def program_paths(comm: str, args: str) -> set[str]:
    """The files a process runs: its program and any absolute path in its args, as given and resolved."""
    out = set()
    for p in [comm, *args.split()]:
        if p.startswith("/"):
            out |= {p, os.path.realpath(p)}
    return out


def served_ports(status: dict | None = None) -> dict[str, str]:
    """Local ports `tailscale serve` fronts: {port: "served" | "funnel"}.

    A loopback listener behind serve is reachable from the tailnet, and
    behind funnel from the internet, so it is not loopback-only.
    Read from `tailscale serve status --json`.
    """
    if status is None:
        out = run(["tailscale", "serve", "status", "--json"], timeout=30)
        status = json.loads(out) if out.strip().startswith("{") else {}
    funnel = {hp for hp, on in (status.get("AllowFunnel") or {}).items() if on}
    ports: dict[str, str] = {}

    def mark(target: str, hostport: str) -> None:
        u = urllib.parse.urlsplit(target if "://" in target else f"tcp://{target}")
        if u.hostname in ("127.0.0.1", "localhost", "::1") and u.port:
            kind = "funnel" if hostport in funnel else "served"
            if ports.get(str(u.port)) != "funnel":
                ports[str(u.port)] = kind

    for port, h in (status.get("TCP") or {}).items():
        if h.get("TCPForward"):
            mark(h["TCPForward"], next((hp for hp in funnel if hp.endswith(f":{port}")), f"tcp:{port}"))
    for hostport, web in (status.get("Web") or {}).items():
        for h in (web.get("Handlers") or {}).values():
            if h.get("Proxy"):
                mark(h["Proxy"], hostport)
    return ports


def link(listeners: list[dict], items: list[dict], served: dict[str, str] | None = None) -> None:
    """Give each listener the items whose install path holds a file it runs."""
    prefixes = [(pre, i) for i in items for pre in ([i["path"]] if i.get("path") else []) + i.get("paths", [])]
    for li in listeners:
        if li["bind"] == "loopback" and (served or {}).get(li["port"]):
            li["bind"] = served[li["port"]]  # served or funnel: reachable beyond this Mac
        hit = {id(i): i for pre, i in prefixes for p in li.get("paths", []) if p.startswith(pre)}
        li["items"] = [[i["source"], i["name"], i["version"]] for i in hit.values()]
        adv = [a for i in hit.values() if i.get("in_use", True) for a in i.get("advisories", [])
               if brewpatch.exposed(a)]  # brew backported the fix: not exposed
        li["exposed"] = bool(adv)
        li["kev"] = any(a["kev"] for a in adv)


def protections() -> dict:
    """FileVault, SIP, Gatekeeper, firewall: 1 on, 0 off, missing if unreadable."""
    checks = {
        "filevault": (["fdesetup", "status"], r"FileVault is On", r"FileVault is Off"),
        "sip": (["csrutil", "status"], r"status: enabled", r"status: disabled"),
        "gatekeeper": (["spctl", "--status"], r"assessments enabled", r"assessments disabled"),
        "firewall": (["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
                     r"enabled|State = [12]", r"disabled|State = 0"),
    }
    out = {}
    for name, (cmd, on, off) in checks.items():
        text = run(cmd, timeout=30)
        if re.search(on, text):
            out[name] = 1
        elif re.search(off, text):
            out[name] = 0
    return out


def macos() -> dict:
    return {"version": run(["sw_vers", "-productVersion"]).strip(),
            "build": run(["sw_vers", "-buildVersion"]).strip()}


def allow_path() -> Path:
    return Path(os.environ.get("PATCHED_ALLOW_SERVICES", str(Path.home() / ".patched/allow/services")))


def allowlist(path: Path | None = None) -> list[dict] | None:
    """The services allow list: `process bind  # why`, one per line; None if there is none.

    Keyed on process and bind, never port: rapportd's ports moved between two
    scans. Loopback needs no entry.
    """
    path = path or allow_path()
    if not path.exists():
        return None
    entries = []
    for n, line in enumerate(path.read_text().splitlines(), 1):
        body, _, why = line.partition("#")
        words = body.split()
        if not words:
            continue
        if len(words) != 2:
            raise ValueError(f"{path}:{n}: want `process bind  # why`, got {line!r}")
        entries.append({"process": words[0], "bind": words[1], "why": why.strip()})
    return entries


def allow(listeners: list[dict], entries: list[dict] | None) -> None:
    """Mark each listener allowed if loopback, or if its process and bind are listed."""
    keys = {(e["process"], e["bind"]) for e in entries or []}
    for li in listeners:
        li["allowed"] = li["bind"] == "loopback" or (li["process"], li["bind"]) in keys
