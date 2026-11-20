"""The allow lists: config layers, services, products. No real system state."""
from __future__ import annotations

from pathlib import Path

import pytest

from patched import allow, collect


def layout(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        f = root / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
    return root


def test_layers_fleet_class_host(tmp_path: Path) -> None:
    root = layout(tmp_path, {"host/host1/class": "# the class\nlaptop  # a laptop\n"})
    assert [label for label, _ in allow.layers("host1", root)] == ["fleet", "class/laptop", "host/host1"]
    assert [label for label, _ in allow.layers("host2", root)] == ["fleet", "host/host2"]


@pytest.mark.parametrize("bad", ["../etc", "a/b", ""])
def test_a_host_or_class_is_one_path_segment(tmp_path: Path, bad: str) -> None:
    with pytest.raises(ValueError):
        allow.host_class(bad, tmp_path)
    layout(tmp_path, {"host/host1/class": f"{bad or '..'}\n"})
    with pytest.raises(ValueError):
        allow.host_class("host1", tmp_path)


def test_services_are_the_union_of_layers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATCHED_ALLOW_SERVICES", str(tmp_path / "old"))
    root = layout(tmp_path / "config", {
        "fleet/services": "rapportd any  # Continuity\n",
        "host/host1/class": "laptop\n",
        "class/laptop/services": "grafana served  # the board\n",
        "host/host1/services": "fileshare served  # files\n",
        "host/other/services": "sshd any  # not host1's\n",
    })
    entries, files = allow.services("host1", root)
    assert [(e["process"], e["layer"]) for e in entries] == [
        ("rapportd", "fleet"), ("grafana", "class/laptop"), ("fileshare", "host/host1")]
    assert len(files) == 3


def test_services_fall_back_to_the_old_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    old = tmp_path / "old"
    old.write_text("rapportd any  # Continuity\n")
    monkeypatch.setenv("PATCHED_ALLOW_SERVICES", str(old))
    entries, files = allow.services("host1", tmp_path / "no-config")
    assert [e["process"] for e in entries] == ["rapportd"] and files == [str(old)]
    old.unlink()
    assert allow.services("host1", tmp_path / "no-config") == (None, [])


def test_strip_comment_keeps_a_hash_inside_quotes() -> None:
    assert allow.strip_comment('brew "a#b"  # why') == ('brew "a#b"  ', "why")
    assert allow.strip_comment("plain") == ("plain", "")


def test_old_reader_is_unchanged(tmp_path: Path) -> None:
    f = tmp_path / "services"
    f.write_text("x any  # y\n")
    assert collect.allowlist(f) == [{"process": "x", "bind": "any", "why": "y"}]


MIXED = (
    "# a comment",
    'tap "oven-sh/bun"',
    'tap "someone/tools", "https://github.com/someone/tools"',
    'brew "jq"  # JSON',
    'brew "hashicorp/tap/terraform"',
    'cask "ghostty", greedy: true',
    'mas "Xcode", id: 497799835',
    'uv "patched", source: "git+ssh://git.example/~/git/repos/patched.git"',
    'uv "speech-kit", with: ["phonemes", "uvicorn"]',
    'brew "x" if OS.mac?',
    'instance_eval(File.read("other"))',
    'brew "y", args: ["with-z"], restart_service: :changed',
    'nonsense "z"',
)


def test_brewfile_reads_plain_entries_and_counts_the_rest(tmp_path: Path) -> None:
    f = tmp_path / "Brewfile"
    f.write_text("\n".join(MIXED) + "\n")
    entries, errors = allow.read_brewfile(f, "fleet")
    assert [(e["type"], e["name"]) for e in entries] == [
        ("tap", "oven-sh/bun"), ("tap", "someone/tools"), ("brew", "jq"), ("brew", "hashicorp/tap/terraform"),
        ("cask", "ghostty"), ("mas", "Xcode"), ("uv", "patched"), ("uv", "speech-kit")]
    assert entries[1]["options"] == {"url": "https://github.com/someone/tools"}
    assert entries[2]["why"] == "JSON" and entries[2]["where"].endswith(":4")
    assert entries[5]["options"] == {"id": 497799835}
    assert entries[6]["options"]["source"].startswith("git+ssh://")
    assert entries[7]["options"]["with"] == ["phonemes", "uvicorn"]
    assert len(errors) == 4  # the if, the instance_eval, the :symbol, the unknown type


def test_products_merge_every_layer(tmp_path: Path) -> None:
    root = layout(tmp_path, {
        "fleet/Brewfile": 'brew "jq"\n',
        "host/host1/class": "laptop\n",
        "class/laptop/Brewfile": 'cask "ghostty"\n',
        "host/host1/Brewfile": 'npm "wrangler"\nbrew "x" if true\n',
        "host/host1/apps": "Visual Studio Code  # the editor\nZoom.app\n",
    })
    p = allow.products("host1", root)
    assert p["loaded"] and p["class"] == "laptop" and len(p["files"]) == 4
    assert [(e["type"], e["name"], e["layer"]) for e in p["entries"]] == [
        ("brew", "jq", "fleet"), ("cask", "ghostty", "class/laptop"), ("npm", "wrangler", "host/host1"),
        ("app", "Visual Studio Code", "host/host1"), ("app", "Zoom", "host/host1")]
    assert len(p["errors"]) == 1


def test_no_config_loads_nothing(tmp_path: Path) -> None:
    p = allow.products("host1", tmp_path / "missing")
    assert p["loaded"] is False and p["entries"] == []


def test_an_empty_layer_file_alone_keeps_the_old_list(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty fleet/services alone must not drop the old file."""
    old = tmp_path / "old"
    old.write_text("rapportd any  # Continuity\n")
    monkeypatch.setenv("PATCHED_ALLOW_SERVICES", str(old))
    root = layout(tmp_path / "config", {"fleet/services": "# comments only\n"})
    entries, files = allow.services("host1", root)
    assert [e["process"] for e in entries] == ["rapportd"] and files == [str(old)]
    old.unlink()  # the move is done: the layers rule, even empty
    assert allow.services("host1", root) == ([], [str(root / "fleet/services")])


def test_a_dangling_config_link_fails_loudly(tmp_path: Path) -> None:
    """A broken link is an error, not "no config"."""
    link = tmp_path / "config"
    link.symlink_to(tmp_path / "gone")
    with pytest.raises(FileNotFoundError, match="gone"):
        allow.services("host1", link)
    with pytest.raises(FileNotFoundError):
        allow.products("host1", link)


def test_single_quotes_read_like_double(tmp_path: Path) -> None:
    """brew 'x' is a Brewfile entry too, and a # inside quotes is no comment."""
    assert allow.strip_comment("brew 'a#b'  # why") == ("brew 'a#b'  ", "why")
    assert allow.strip_comment("""brew "it's#x" # y""") == ('''brew "it's#x" ''', "y")
    f = tmp_path / "Brewfile"
    f.write_text("brew 'jq'\ntap 'a/b', 'https://x/y'\nuv 'p', source: 'git+https://h/p.git'\n")
    entries, errors = allow.read_brewfile(f, "fleet")
    assert errors == []
    assert [(e["name"], e["options"]) for e in entries] == [
        ("jq", {}), ("a/b", {"url": "https://x/y"}), ("p", {"source": "git+https://h/p.git"})]


def test_loaded_means_a_list_was_read(tmp_path: Path) -> None:
    """A README-only config is not a loaded list."""
    root = layout(tmp_path, {"README.md": "# config\n"})
    assert allow.products("host1", root)["loaded"] is False


def test_an_app_line_splits_on_any_hash(tmp_path: Path) -> None:
    """An app line ends at the first #, quotes or not."""
    f = tmp_path / "apps"
    f.write_text('Weird "App  # why\n')
    assert [(e["name"], e["why"]) for e in allow.read_apps(f, "host/host1")] == [('Weird "App', "why")]


@pytest.mark.parametrize("a,b", [
    ("git.example:git/repos/p.git", "git+ssh://git.example/~/git/repos/p.git"),
    ("git+https://github.com/NVIDIA/s.git?rev=091a", "https://github.com/NVIDIA/s"),
    ("ssh://git@git.example:22/git/repos/p", "git.example:git/repos/p"),
])
def test_git_identity_one_repo_many_spellings(a: str, b: str) -> None:
    assert allow.git_identity(a) == allow.git_identity(b) is not None


@pytest.mark.parametrize("bad", [None, "", "file:///Users/someone/foo", "/Users/someone/foo", "patched"])
def test_git_identity_refuses_what_is_not_a_repo(bad: str | None) -> None:
    assert allow.git_identity(bad) is None


def formula(name: str, on_request: bool, deps: tuple = (), full: str | None = None, aliases: tuple = ()) -> dict:
    return {"source": "brew-formula", "name": name, "full_name": full or name,
            "on_request": on_request, "deps": list(deps), "aliases": list(aliases)}


ITEMS = [
    formula("a", True, ("b",)), formula("b", False),
    formula("c", True, ("d",)), formula("d", False),
    formula("e", False),                                    # an orphan: nobody asked, nobody needs it
    formula("t", True, full="x/tap/t"),                     # listed from another tap: no
    formula("z", True, aliases=("oldz",)),                  # listed by its old name: yes
    formula("m", False),                                    # needed by an allowed cask
    {"source": "brew-cask", "name": "k", "full_name": "k", "formula_deps": ["m"]},
    {"source": "uv-tool", "name": "p", "local": True, "origin": "git.example:git/repos/p.git"},
    {"source": "uv-tool", "name": "q", "local": True, "origin": None},
    {"source": "uv-tool", "name": "r", "local": False},
    {"source": "uv-tool", "name": "s", "local": False},     # listed with a source, but from PyPI: no
    {"source": "npm-global", "name": "n"},
    {"source": "app", "name": "Zoom"}, {"source": "app", "name": "Xcode"},
    {"source": "launchd", "name": "ignored"},
]
LISTED = [
    'brew "a"', 'brew "y/tap/t"', 'brew "oldz"', 'cask "k"', 'tap "x/tap"', 'go "golang.org/x/tools"',
    'uv "p", source: "git+ssh://git.example/~/git/repos/p.git"', 'uv "q"', 'uv "r"',
    'uv "s", source: "git+https://h/s.git"', 'npm "n"', 'mas "Xcode", id: 497799835',
]


def test_match_follows_the_keep_rule(tmp_path: Path) -> None:
    root = layout(tmp_path, {"fleet/Brewfile": "\n".join(LISTED) + "\n", "host/host1/apps": "Zoom\n"})
    items = [dict(i) for i in ITEMS]
    r = allow.match(items, allow.products("host1", root))
    got = {i["name"]: i.get("allowed") for i in items}
    assert got == {"a": True, "b": True, "c": False, "d": False, "e": False, "t": False, "z": True,
                   "m": True, "k": True, "p": True, "q": False, "r": True, "s": False, "n": True,
                   "Zoom": True, "Xcode": True, "ignored": None}
    assert r["unallowed"] == {"brew-formula": ["c", "e", "t"], "brew-cask": [], "uv-tool": ["q", "s"],
                              "npm-global": [], "app": []}
    assert r["riding"] == ["d"]
    by = {i["name"]: i for i in items}
    assert by["d"]["under"] == ["c"] and by["b"]["allowed_by"] == "needed by a"
    assert by["m"]["allowed_by"] == "needed by cask k" and by["a"]["allowed_by"].endswith("Brewfile:1")


def test_npm_lines_compare_whole_names(tmp_path: Path) -> None:
    """A scoped npm package is one name, never a tap."""
    lines = 'npm "@acme/spec"\nnpm "wrangler"\nnpm "code-agent"\n'
    root = layout(tmp_path, {"fleet/Brewfile": lines})
    items = [{"source": "npm-global", "name": n} for n in
             ("@acme/spec", "wrangler", "@acme/code-agent", "@other/spec")]
    r = allow.match(items, allow.products("host1", root))
    assert [i["allowed"] for i in items] == [True, True, False, False]
    assert r["unallowed"]["npm-global"] == ["@acme/code-agent", "@other/spec"]


def test_a_bare_line_names_core_only(tmp_path: Path) -> None:
    """A tap product that takes a core name never rides on the core line."""
    lines = ['brew "terraform"', 'brew "tf"', 'brew "jq"', 'brew "hashicorp/tap/packer"', 'cask "k2"']
    root = layout(tmp_path, {"fleet/Brewfile": "\n".join(lines) + "\n"})
    items = [
        formula("terraform", True, full="evil/tap/terraform"),       # a name squat: no
        formula("tf2", True, full="evil/tap/tf2", aliases=("tf",)),  # by alias, still a tap: no
        formula("jq", True),                                         # core: yes
        formula("packer", True, full="hashicorp/tap/packer"),        # qualified line: yes
        {"source": "brew-cask", "name": "k2", "full_name": "evil/tap/k2"},  # a tap cask: no
    ]
    allow.match(items, allow.products("host1", root))
    assert [i["allowed"] for i in items] == [False, False, True, True, False]


def test_uv_lines_name_the_package(tmp_path: Path) -> None:
    """Extras and spelling don't hide a uv tool: `huggingface-hub[cli]` is huggingface-hub."""
    lines = 'uv "huggingface-hub[cli]"\nuv "Foo_Bar"\nuv "text-gen"\n'
    root = layout(tmp_path, {"fleet/Brewfile": lines})
    items = [{"source": "uv-tool", "name": n, "local": False} for n in ("huggingface-hub", "foo-bar", "speech-to-text")]
    allow.match(items, allow.products("host1", root))
    assert [i["allowed"] for i in items] == [True, True, False]
    assert {allow.pypi_name(s) for s in ("ruff>=0.5", "Ruff[x] ~= 1", "ruff @ git+https://h/r", "ruff;os")} == {"ruff"}
    plist = allow.products("host1", root)
    wanted = [{"type": "uv", "name": "huggingface_hub", "options": {}}]
    assert allow.diff(wanted, plist)["not_allowed"] == []


def test_brews_own_taps_are_named_bare(tmp_path: Path) -> None:
    """`brew "homebrew/core/jq"` is jq; core's full_name is bare."""
    root = layout(tmp_path, {"fleet/Brewfile": 'brew "homebrew/core/jq"\ncask "homebrew/cask/k"\n'})
    items = [formula("jq", True), {"source": "brew-cask", "name": "k", "full_name": "k"}]
    allow.match(items, allow.products("host1", root))
    assert [i["allowed"] for i in items] == [True, True]
    plist = layout(tmp_path / "b", {"fleet/Brewfile": 'brew "jq"\n'})
    wanted, _ = allow.read_brewfile(root / "fleet/Brewfile", "file")
    assert allow.diff(wanted[:1], allow.products("host1", plist))["not_allowed"] == []


def test_no_list_allows_nothing(tmp_path: Path) -> None:
    items = [dict(i) for i in ITEMS]
    r = allow.match(items, allow.products("host1", tmp_path / "none"))
    assert r["loaded"] is False and r["riding"] == ["b", "d", "m"]
    assert sum(len(v) for v in r["unallowed"].values()) == 13
