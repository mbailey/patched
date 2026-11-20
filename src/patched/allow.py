"""The allow lists: what may be installed (products) and what may listen (services).

Config lives in git: `~/.patched/config` links to a checkout of your
config repo; data (scans, cache) stays in
`~/.patched`. Three layers, each a directory: `fleet/`, `class/NAME/` and
`host/NAME/`, where `host/NAME/class` names the box's class. Allowed is the
union of the three; there are no deny lines in v1.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from . import collect

NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")  # a host or class: one path segment


def config_dir() -> Path:
    return Path(os.environ.get("PATCHED_CONFIG", str(Path.home() / ".patched/config")))


def strip_comment(line: str) -> tuple[str, str]:
    """(code, comment): the first # outside quotes ("..." or '...') starts the comment."""
    quote = ""
    for i, ch in enumerate(line):
        if ch in "\"'" and quote in ("", ch):
            quote = "" if quote else ch
        elif ch == "#" and not quote:
            return line[:i], line[i + 1:].strip()
    return line, ""


def check_link(root: Path) -> None:
    """A dangling config link is an error, never a quiet "no config"."""
    if root.is_symlink() and not root.exists():
        raise FileNotFoundError(f"{root} links to {os.readlink(root)}, which is missing")


def host_class(host: str, root: Path | None = None) -> str | None:
    """The class named in host/HOST/class (its first word), or None."""
    root = root or config_dir()
    if not NAME.match(host):
        raise ValueError(f"host {host!r} is not one path segment")
    f = root / "host" / host / "class"
    if not f.is_file():
        return None
    for line in f.read_text().splitlines():
        word = strip_comment(line)[0].strip()
        if word:
            if not NAME.match(word):
                raise ValueError(f"{f}: class {word!r} is not one path segment")
            return word
    return None


def layers(host: str, root: Path | None = None) -> list[tuple[str, Path]]:
    """(label, directory) for fleet, the box's class if it has one, and the host."""
    root = root or config_dir()
    out = [("fleet", root / "fleet")]
    cls = host_class(host, root)
    if cls:
        out.append((f"class/{cls}", root / "class" / cls))
    out.append((f"host/{host}", root / "host" / host))
    return out


def services(host: str, root: Path | None = None) -> tuple[list[dict] | None, list[str]]:
    """The services allow list and the files it came from.

    From the config layers when any of them has a `services` file (their
    union); else from the old single file (`~/.patched/allow/services`), so
    no scan goes blind while the list moves. None when there is neither.

    The layers take over only when one of their files has an entry, or once
    the old file is gone. fleet/services may start empty, and an empty
    file on its own must not drop the old list.
    The fallback is for the move only: the old file must go once the layers
    are in use, or an emptied list would quietly bring it back.
    """
    root = root or config_dir()
    check_link(root)
    files = [(label, d / "services") for label, d in layers(host, root)] if root.is_dir() else []
    files = [(label, f) for label, f in files if f.is_file()]
    entries = [{**e, "layer": label} for label, f in files for e in collect.allowlist(f) or []]
    old = collect.allow_path()
    if files and (entries or not old.exists()):
        return entries, [str(f) for _, f in files]
    return collect.allowlist(old), [str(old)] if old.exists() else []


# --- products: a Brewfile per layer, plus `apps` for what brew can't name ---

TYPES = {"tap", "brew", "cask", "mas", "uv", "npm", "go", "cargo", "vscode", "flatpak", "krew", "winget"}
STR = r"""(?:"[^"]*"|'[^']*')"""
ENTRY = re.compile(rf"^([a-z]+)\s+({STR})\s*(?:,\s*(.*))?$")
TAP_URL = re.compile(rf"^({STR})\s*(?:,\s*(.*))?$")  # tap "user/repo", "url", ...
CORE = re.compile(r"^homebrew/(?:core|cask)/")  # brew's own taps: their products are named bare
OPTION = re.compile(rf"\s*([a-z_]+):\s*({STR}|\d+|true|false|\[[^\]]*\])\s*(?:,|$)")


def options(text: str) -> dict | None:
    """`key: value, ...` as a dict; None if any part is not a plain option.

    Values are a string, an integer, true or false, or a list of strings.
    Anything else (a method call, an `if`) is Ruby, which patched never runs.
    """
    opts, pos, text = {}, 0, text.strip()
    while pos < len(text):
        m = OPTION.match(text, pos)
        if not m or m.end() == pos:
            return None
        key, raw = m.groups()
        if raw[0] in "\"'":
            value: object = raw[1:-1]
        elif raw in ("true", "false"):
            value = raw == "true"
        elif raw.isdigit():
            value = int(raw)
        else:
            parts = [p.strip() for p in raw[1:-1].split(",") if p.strip()]
            if not all(re.fullmatch(STR, p) for p in parts):
                return None
            value = [p[1:-1] for p in parts]
        opts[key] = value
        pos = m.end()
    return opts


def read_brewfile(path: Path, layer: str) -> tuple[list[dict], list[str]]:
    """(entries, errors): one plain `type "name"` entry per line; never run as Ruby."""
    entries, errors = [], []
    for n, raw in enumerate(path.read_text().splitlines(), 1):
        code, why = strip_comment(raw)
        code = code.strip()
        if not code:
            continue
        m = ENTRY.match(code)
        rest = (m.group(3) or "") if m else ""
        url = None
        if m and m.group(1) == "tap" and (u := TAP_URL.match(rest)):
            rest, url = u.group(2) or "", u.group(1)[1:-1]
        opts = options(rest) if m else None
        if opts is not None and url:
            opts["url"] = url
        if not m or m.group(1) not in TYPES or opts is None:
            errors.append(f"{path}:{n}: not a plain Brewfile entry: {code[:60]!r}")
            continue
        name = m.group(2)[1:-1]
        if m.group(1) in ("brew", "cask"):
            name = CORE.sub("", name)
        entries.append({"type": m.group(1), "name": name, "options": opts,
                        "why": why, "layer": layer, "where": f"{path}:{n}"})
    return entries, errors


def read_apps(path: Path, layer: str) -> list[dict]:
    """`App Name  # why`, one per line: the app bundle's name without .app."""
    entries = []
    for n, raw in enumerate(path.read_text().splitlines(), 1):
        code, _, why = raw.partition("#")  # app names never hold a quoted #
        name, why = code.strip().removesuffix(".app"), why.strip()
        if name:
            entries.append({"type": "app", "name": name, "options": {}, "why": why,
                            "layer": layer, "where": f"{path}:{n}"})
    return entries


def products(host: str, root: Path | None = None) -> dict:
    """The product allow list: every layer's Brewfile and apps, merged.

    `loaded` is False unless a Brewfile or apps file was read: then nothing
    is allowed, and the board says why (patched_allowlist_loaded 0).
    """
    root = root or config_dir()
    check_link(root)
    out: dict = {"loaded": root.is_dir(), "config": str(root), "host": host,
                 "class": None, "files": [], "entries": [], "errors": []}
    if not out["loaded"]:
        return out
    out["class"] = host_class(host, root)
    for label, d in layers(host, root):
        bf, ap = d / "Brewfile", d / "apps"
        if bf.is_file():
            entries, errors = read_brewfile(bf, label)
            out["entries"] += entries
            out["errors"] += errors
            out["files"].append(str(bf))
        if ap.is_file():
            out["entries"] += read_apps(ap, label)
            out["files"].append(str(ap))
    out["loaded"] = bool(out["files"])  # a list was read, not just a directory found
    return out


# --- the matcher: each product allowed or not ---

PRODUCT_SOURCES = ("brew-formula", "brew-cask", "uv-tool", "npm-global", "app")


def git_identity(url: str | None) -> tuple[str, str] | None:
    """(host, path) of a git URL in any spelling, so git.example:git/repos/x.git and
    git+ssh://git.example/~/git/repos/x.git are one repo. None if it is not one."""
    u = re.sub(r"[?#].*$", "", (url or "").strip().removeprefix("git+"))
    m = (re.match(r"^(?:ssh|https?|git)://(?:[^@/]+@)?([^/:]+)(?::\d+)?/(.+)$", u)
         or re.match(r"^(?:[^@/:]+@)?([^/:]+):(?!//)(.+)$", u))
    if not m:
        return None
    path = re.sub(r"^/*(~/)?", "", m.group(2)).removesuffix("/").removesuffix(".git")
    return (m.group(1).lower(), path) if path else None


def pypi_name(spec: str) -> str:
    """A uv line's package as uv names the tool: extras, a version or a URL
    dropped, then PEP 503 normalized, so `huggingface-hub[cli]`,
    `Huggingface_Hub` and `huggingface-hub>=0.20` are one tool."""
    return re.sub(r"[-_.]+", "-", re.split(r"[\[<>=!~;@ ]", spec, maxsplit=1)[0].strip()).lower()


def _named(kind: str, entry: str, names: tuple, full: str | None) -> bool:
    """Does a list line name this product (by its name, an alias or an old name)?

    npm, app and mas lines compare whole names, so a scoped npm package
    (`@scope/pkg`) is one name, never a tap. A brew or cask line
    that is tap-qualified names only that tap's product; a bare
    one names only a core product. A tap formula that takes a core name
    must not ride on the core line, and for a bare line `brew bundle`
    itself installs core's. It fails closed: a bare line for a
    tap product allows nothing, and the fix is to qualify the line.
    """
    if kind not in ("brew", "cask"):
        return entry in names
    if "/" in entry:
        return entry == full
    return entry in names and full is not None and "/" not in full


def match(items: list[dict], plist: dict) -> dict:
    """Mark each product allowed or not, and say why; return the counts.

    Formulae follow Homebrew's own keep rule (cleanup.rb, kept_formulae): the
    listed ones, the formulae a listed cask needs, and every run-time
    dependency of those, by name, alias or old name. A formula that is not
    allowed and was only pulled in by others rides with them: it is shown
    under them and not counted. A uv tool built from our own repo matches
    only a line whose source names that repo. Taps and go, cargo and
    vscode lines allow nothing patched scans.
    """
    entries: dict[str, list[dict]] = {}
    for e in plist["entries"]:
        entries.setdefault(e["type"], []).append(e)

    def find(kind: str, name: str, full: str | None = None, aliases: tuple = ()) -> dict | None:
        for e in entries.get(kind, []):
            if _named(kind, e["name"], (name, *aliases), full):
                return e
        return None

    # Keyed by short name, as Homebrew's own deps are (rsplit below): two
    # taps' formulae with one short name would merge. Rare, and accepted.
    formulae: dict[str, dict] = {}
    for i in items:
        if i["source"] == "brew-formula":
            f = formulae.setdefault(i["name"], {"on_request": False, "deps": set(), "item": i})
            f["on_request"] |= bool(i.get("on_request"))
            f["deps"] |= set(i.get("deps") or ())
    kept: dict[str, str] = {}
    for name, f in formulae.items():
        i = f["item"]
        e = find("brew", name, i.get("full_name"), tuple(i.get("aliases") or ()))
        if e:
            kept[name] = e["where"]
    dependents: dict[str, set[str]] = {}
    for i in items:
        if i["source"] != "brew-cask":
            continue
        e = find("cask", i["name"], i.get("full_name"), tuple(i.get("aliases") or ()))
        for d in i.get("formula_deps") or []:
            dependents.setdefault(d, set()).add(f"cask {i['name']}")
            if e:
                kept.setdefault(d, f"needed by cask {i['name']}")
    for name, f in formulae.items():
        for d in f["deps"]:
            dependents.setdefault(d, set()).add(name)
    todo = list(kept)
    while todo:
        n = todo.pop()
        for d in formulae.get(n, {}).get("deps", ()):
            if d not in kept:
                kept[d] = f"needed by {n}"
                todo.append(d)

    unallowed: dict[str, set[str]] = {s: set() for s in PRODUCT_SOURCES}
    riding: set[str] = set()
    for i in items:
        src, name = i["source"], i["name"]
        if src not in PRODUCT_SOURCES:
            continue
        by: str | None = None
        if src == "brew-formula":
            by = kept.get(name)
        elif src == "brew-cask":
            e = find("cask", name, i.get("full_name"), tuple(i.get("aliases") or ()))
            by = e and e["where"]
        elif src == "uv-tool":
            for e in entries.get("uv", []):
                source = e["options"].get("source")
                if pypi_name(e["name"]) != pypi_name(name):
                    continue
                if i.get("local"):
                    mine = git_identity(i.get("origin"))
                    if mine and git_identity(source) == mine:
                        by = e["where"]
                elif not source:
                    by = e["where"]
                if by:
                    break
        elif src == "npm-global":
            e = find("npm", name)
            by = e and e["where"]
        else:  # app: an apps line, or a mas line by its name
            e = find("app", name) or find("mas", name)
            by = e and e["where"]
        i["allowed"] = bool(by)
        i.pop("allowed_by", None)
        i.pop("under", None)
        if by:
            i["allowed_by"] = by
        elif src == "brew-formula" and not formulae[name]["on_request"] and dependents.get(name):
            i["under"] = sorted(dependents[name])
            riding.add(name)
        else:
            unallowed[src].add(name)
    return {"loaded": plist["loaded"], "files": plist["files"], "class": plist["class"],
            "entries": len(plist["entries"]), "errors": plist["errors"],
            "unallowed": {s: sorted(v) for s, v in unallowed.items()}, "riding": sorted(riding)}


# --- for the CLI: an entry as Brewfile text; an install list against the list ---

UNSCANNED = {"tap", "go", "cargo", "vscode", "flatpak", "krew", "winget"}  # patched scans none of these


def line(e: dict) -> str:
    """An entry as Brewfile text: `uv "x", source: "..."`. An apps line reads `app "Zoom"`."""
    opts = dict(e["options"])
    out = [f'{e["type"]} "{e["name"]}"']
    if e["type"] == "tap" and "url" in opts:
        out.append(f'"{opts.pop("url")}"')
    for k, v in opts.items():
        if isinstance(v, bool):
            v = "true" if v else "false"
        elif isinstance(v, list):
            v = "[" + ", ".join(f'"{x}"' for x in v) + "]"
        elif isinstance(v, str):
            v = f'"{v}"'
        out.append(f"{k}: {v}")
    return ", ".join(out)


def names(a: dict, e: dict) -> bool:
    """Does allow line `a` name what install line `e` installs? By the matcher's
    rules, but by name only: with no brew info, aliases are not resolved."""
    t, n = e["type"], e["name"]
    if t in ("brew", "cask"):
        return a["type"] == t and _named(t, a["name"], (n.rsplit("/", 1)[-1],), n)
    if t == "uv":
        if a["type"] != "uv" or pypi_name(a["name"]) != pypi_name(n):
            return False
        mine, theirs = e["options"].get("source"), a["options"].get("source")
        if not mine:
            return not theirs
        return git_identity(theirs) is not None and git_identity(theirs) == git_identity(mine)
    if t == "mas":
        return a["type"] in ("mas", "app") and a["name"] == n
    return a["type"] == t and a["name"] == n


def diff(wanted: list[dict], plist: dict) -> dict:
    """An install list (a Brewfile) against the allow list.

    `not_allowed`: what it installs that no line allows. `unchecked`: lines
    of a kind patched never scans (taps, go, cargo, ...). `lacking`: allow
    lines it does not name; apps lines aside, since a Brewfile never holds one.
    """
    used: set[str] = set()
    out: dict[str, list[dict]] = {"not_allowed": [], "unchecked": [], "lacking": []}
    for e in wanted:
        if e["type"] in UNSCANNED:
            out["unchecked"].append(e)
            continue
        hits = [a["where"] for a in plist["entries"] if names(a, e)]
        used.update(hits)
        if not hits:
            out["not_allowed"].append(e)
    out["lacking"] = [a for a in plist["entries"]
                      if a["where"] not in used and a["type"] not in UNSCANNED | {"app"}]
    return out
