"""What Homebrew already patched: read the KEG's formula copy.

Every keg carries the formula it was built from at
`<Cellar>/<name>/<version>/.brew/<name>.rb`: the revision that is INSTALLED,
with no subprocess and no network. Homebrew backports upstream fixes as
`patch do` blocks, naming the advisories (`resolves "CVE-..."`) and the
upstream commit (`url ".../commit/<sha>.patch"`, or a `# Backport of
.../commit/<sha>` comment above a `file "Patches/..."` block).

The rule is fail safe: anything this cannot read or parse is None
(unknown), never an empty set, so an advisory is never marked "false" or
dropped on a guess. And it never over-claims: a patch only counts when it
applies to this Mac's build. Inside `on_linux`, `head`, a resource, an
`if`/`unless`, a macOS-version or an other-arch block it does not count.
"""
from __future__ import annotations

import platform
import re
from pathlib import Path

ID = re.compile(r"\b(CVE-\d{4}-\d{4,}|OSV-\d{4}-\d+|GHSA(?:-[0-9a-z]{4}){3})\b", re.IGNORECASE)
COMMIT = re.compile(r"/commits?/([0-9a-fA-F]{7,40})\b")
STRING = re.compile(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'')
HEREDOC = re.compile(r"<<[~-]?(['\"]?)([A-Z_][A-Z0-9_]*)\1")
PCT_OPEN = re.compile(r"%[wWiI]?([\[({<])")
PAIRS = {"[": "]", "(": ")", "{": "}", "<": ">"}
OPENER = re.compile(r"^(if|unless|while|until|case|begin|def|class|module|for)\b"
                    r"|(?:[=(,]|<<)\s*(if|unless|case|begin)\b")  # `args << if ...` opens; `x if y` does not
ENDLESS_DEF = re.compile(r"^def\s+[\w.]+[?!]?\s*(\([^)]*\))?\s*=(?![=~])")  # `def x = y`: no end
DO = re.compile(r"\bdo\s*(\|[^|]*\|)?\s*$")
END = re.compile(r"(?<![.\w:])end\b(?![?!:])")
INTERP = re.compile(r"#\{[^}]*\}")
# Blocks a macOS stable build passes straight through. Everything else that
# holds a patch (on_linux, head, resource, if, on_sonoma ...) is not credited.
TRANSPARENT = {"class", "stable", "on_macos"}
ARCH = {"arm64": "on_arm", "aarch64": "on_arm", "x86_64": "on_intel"}


def formula_path(item: dict) -> Path:
    """The keg's own formula copy: <item path>.brew/<name>.rb."""
    return Path(item["path"]) / ".brew" / f"{item['name']}.rb"


def _code(line: str) -> str:
    """The line with string contents and the trailing comment removed."""
    line = STRING.sub('""', INTERP.sub("", line))
    return line.split("#", 1)[0]


def _head(code: str) -> str:
    m = re.match(r"\s*([a-z_][a-z0-9_]*[?!]?)", code)
    return m.group(1) if m else ""


def parse(text: str, arch: str | None = None) -> dict | None:
    """{"ids": set, "shas": set} of the patches that apply on macOS; None if unparseable."""
    transparent = TRANSPARENT | {ARCH.get(arch or platform.machine(), "on_arm")}
    ids: set[str] = set()
    shas: set[str] = set()
    stack: list[tuple[str, bool]] = []  # (head word, this block and every one around it pass through)
    comments: list[str] = []  # the comment run directly above the current line
    patch: dict | None = None  # the open patch block: its depth, credited, its lines

    def push(head: str) -> None:
        nonlocal patch
        through = all(ok for _, ok in stack)
        if head == "patch" and patch is None:
            patch = {"depth": len(stack), "credited": through, "lines": [], "comments": comments}
        stack.append((head, through and head in transparent))

    def pop() -> bool:
        nonlocal patch
        if not stack:
            return False
        stack.pop()
        if patch is not None and len(stack) == patch["depth"]:
            if patch["credited"]:
                _take(patch, ids, shas)
            patch = None
        return True

    lines = iter(text.splitlines())
    for raw in lines:
        stripped = raw.strip()
        if stripped == "__END__":
            break
        if stripped.startswith("#"):
            comments.append(stripped)
            if patch is not None:
                patch["lines"].append(stripped)
            continue
        if patch is not None:
            patch["lines"].append(raw)
        code = _code(raw)
        # A heredoc or a multi-line %w[] holds data, not code: skip its body.
        m = PCT_OPEN.search(code)
        if m and PAIRS[m.group(1)] not in code[m.end():]:
            close = PAIRS[m.group(1)]
            last = _skip(lines, lambda t, c=close: c in t)
            if last is None:
                return None
            # the closing line goes on as code: `].uniq.map do |p|`
            code = code[:m.start()] + _code(last.split(close, 1)[1])
        for tail in [h.group(2) for h in HEREDOC.finditer(INTERP.sub("", raw))]:  # <<~'EOS' is quoted
            if _skip(lines, lambda t, x=tail: t.strip() == x) is None:
                return None
        opens = bool(OPENER.search(code.strip()) or DO.search(code)) and not ENDLESS_DEF.match(code.strip())
        closes = len(END.findall(code))
        head = _head(code)
        if END.match(code.strip()):  # `end` first (`end.each do`): close, then open
            if not all(pop() for _ in range(closes)):
                return None
            if opens:
                push(head)
        else:  # open first: `patch do`, or a one-line `def x; end`
            if opens:
                push(head)
            if not all(pop() for _ in range(closes)):
                return None
        comments = []
    if stack or patch is not None:
        return None
    return {"ids": ids, "shas": shas}


def _skip(lines, done) -> str | None:
    """Consume lines up to and including the one `done` accepts and return it; None if the text ran out."""
    return next((t for t in lines if done(t)), None)


def _take(patch: dict, ids: set[str], shas: set[str]) -> None:
    """The ids and commit shas one patch block names."""
    for line in patch["comments"]:
        shas.update(s.lower() for s in COMMIT.findall(line))
    for line in patch["lines"]:
        code = line.strip()
        word = _head(code)
        args = [s[1:-1] for s in STRING.findall(code)]
        if word == "url":
            shas.update(s.lower() for a in args for s in COMMIT.findall(a))
        elif word == "resolves":
            ids.update(a.upper() for a in args if ID.fullmatch(a))
        elif word in ("file", "apply"):
            ids.update(m.upper() for a in args for m in ID.findall(Path(a).name))
        elif code.startswith("#"):
            shas.update(s.lower() for s in COMMIT.findall(code))


def read(item: dict, arch: str | None = None) -> dict | None:
    """The keg formula's patches, or None (unknown) if it can't be read or parsed."""
    try:
        text = formula_path(item).read_text()
    except (OSError, UnicodeDecodeError, KeyError, TypeError):
        return None
    try:
        return parse(text, arch)
    except Exception:  # noqa: BLE001 - a formula we can't parse is unknown, never "no patches"
        return None


def matches(adv: dict, patches: dict) -> bool:
    """Any advisory id in the patch ids, or any fix commit prefix-matching a patch sha."""
    if {i.upper() for i in adv.get("ids") or [adv["advisory"]]} & patches["ids"]:
        return True
    for c in adv.get("fix_commits", []):
        for s in patches["shas"]:
            a, b = c.lower(), s.lower()
            if min(len(a), len(b)) >= 7 and (a.startswith(b) or b.startswith(a)):
                return True
    return False


def mark(items: list[dict], arch: str | None = None) -> None:
    """Set each advisory's patched_by_brew: true | false | unknown (brew) or n/a.

    Everything is decided first and written last, so a failure part way
    leaves every advisory as osv.match left it: unknown, counted exposed.
    An item whose advisories are ALL brew-patched becomes status "patched".
    """
    cache: dict[str, dict | None] = {}
    plan: list[tuple[dict, list[str]]] = []
    for it in items:
        advs = it.get("advisories") or []
        if not advs:
            continue
        if it.get("source") != "brew-formula":
            plan.append((it, ["n/a"] * len(advs)))
            continue
        key = str(it.get("path"))
        if key not in cache:
            cache[key] = read(it, arch)
        p = cache[key]
        plan.append((it, ["unknown" if p is None else ("true" if matches(a, p) else "false") for a in advs]))
    for it, marks in plan:
        for a, v in zip(it["advisories"], marks):
            a["patched_by_brew"] = v
        if it.get("status") == "exposed" and all(v == "true" for v in marks):
            it["status"] = "patched"


def exposed(adv: dict) -> bool:
    """Not brew-patched: still a live exposure (unknown and false both count)."""
    return adv.get("patched_by_brew") != "true"
