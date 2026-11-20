"""Advisories brew already patched, and fixes that are a commit only.

Fixtures only, no network and no live brew: tests/fixtures/libssh2/ holds a
copy of a real keg formula /opt/homebrew/Cellar/libssh2/1.11.1_7/.brew/libssh2.rb
and the 15 OSV records ~/.patched/cache/vulns/ held for it.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from patched import brewpatch, cli, collect, export, osv, scan

FIX = Path(__file__).parent / "fixtures" / "libssh2"
REPO = "https://github.com/libssh2/libssh2"
RECORDS = {p.stem: json.loads(p.read_text()) for p in sorted((FIX / "osv").glob("*.json"))}
BY_ID = {"CVE-2026-58050", "CVE-2026-58051"}  # their cached records carry no fixed event
BY_EVENTS = {"OSV-2025-90", "OSV-2025-92", "OSV-2022-24", "OSV-2024-847"}  # commits in `events` only
NO_FIX = "OSV-2025-433"


def keg(tmp_path: Path, text: str | None = None, name: str = "libssh2", version: str = "1.11.1_7") -> dict:
    """A brew-formula item as collect.brew makes it, its keg under tmp_path."""
    path = tmp_path / "Cellar" / name / version
    (path / ".brew").mkdir(parents=True)
    if text is None:
        shutil.copy(FIX / "libssh2.rb", path / ".brew" / f"{name}.rb")
    else:
        (path / ".brew" / f"{name}.rb").write_text(text)
    return collect.item("brew-formula", name, version, ["GIT", REPO, collect.strip_revision(version)],
                        path=f"{path}/", ids={"brew": name, "git": REPO}, in_use=True, outdated=False)


@pytest.fixture
def osv_stub(monkeypatch: pytest.MonkeyPatch) -> None:
    """OSV answers from the fixtures: every libssh2 query hits all 15 records."""
    monkeypatch.setattr(osv, "_known", lambda pkgs: dict.fromkeys(pkgs, True))
    monkeypatch.setattr(osv, "_batch", lambda qs: [[{"id": i, "modified": r["modified"]}
                                                    for i, r in RECORDS.items()] for _ in qs])
    monkeypatch.setattr(osv, "_vuln", lambda vid, mod: RECORDS[vid])
    monkeypatch.setattr(osv, "_all_records", lambda p: pytest.fail("no versionless fetch expected"))


def scan_of(items: list[dict], **stages: bool) -> dict:
    ok = {"osv": True, "brew_patches": True, "brew": True, "apps": True, "uv": True, "npm": True,
          "listeners": True, "launchd": True, **stages}
    return {"started": 0.0, "finished": 1.0, "stages": ok, "items": items, "listeners": [],
            "launchd": [], "protections": {}, "kev": None}


def lines(prom: str, name: str) -> list[str]:
    return [ln for ln in prom.splitlines() if ln.startswith(name + "{")]


# --- the parser, on the real formula ---------------------------------------

def test_libssh2_formula_names_every_backport() -> None:
    p = brewpatch.parse((FIX / "libssh2.rb").read_text(), arch="arm64")
    assert p["ids"] == {r for r in RECORDS if r != NO_FIX}
    assert {s[:8] for s in p["shas"]} == {"2dae3024", "256d04b6", "17626857", "97acf3df", "34497525",
                                          "a9758da4", "5e477614", "a2ed82d4", "a13bb6c7", "42e33d81",
                                          "631e2f82", "b89858b8"}
    assert all(len(s) == 40 for s in p["shas"])


FORMULA = '''class Foo < Formula
  url "https://example.org/foo-1.0.tar.gz"
  # Fix for https://example.org/issues/1, see also https://github.com/foo/foo/pull/9
  patch do
    url "https://github.com/foo/foo/commit/aaaaaaaa11111111.patch?full_index=1"
    resolves "CVE-2026-1001", "https://github.com/foo/foo/issues/7"
  end

  # Backport of https://github.com/foo/foo/commit/bbbbbbbb22222222
  patch :p0 do
    file "Patches/foo/GHSA-abcd-efgh-ijkl.patch"
  end

  on_macos do
    patch do
      url "https://gitlab.com/foo/foo/-/commit/cccccccc33333333.diff"
      resolves "OSV-2026-5"
    end
  end

  on_linux do
    patch do
      url "https://github.com/foo/foo/commit/dddddddd44444444.patch"
      resolves "CVE-2026-1002"
    end
  end

  head do
    url "https://github.com/foo/foo.git"
    patch do
      resolves "CVE-2026-1003"
    end
  end

  on_intel do
    patch do
      resolves "CVE-2026-1004"
    end
  end

  # https://github.com/foo/foo/commit/eeeeeeee55555555 (patch :DATA carries nothing)
  patch :DATA

  def install
    args = %W[
      --prefix=#{prefix}
      --enable-end
    ].uniq.map do |a|
      a
    end
    args << if OS.mac?
      "--mac"
    else
      "--other"
    end
    (testpath/"t.c").write <<~'EOS'
      int main(void) { do_it(); end_it(); }
    EOS
    system "make" if build.head?
  end

  def name_of = "foo"
end
__END__
diff --git a/x b/x
patch do
'''


def test_shapes_and_platform_blocks() -> None:
    p = brewpatch.parse(FORMULA, arch="arm64")
    # resolves URLs are not ids; GHSA from the file name; on_macos counts
    assert p["ids"] == {"CVE-2026-1001", "GHSA-ABCD-EFGH-IJKL", "OSV-2026-5"}
    assert p["shas"] == {"aaaaaaaa11111111", "bbbbbbbb22222222", "cccccccc33333333"}  # not :DATA's eeee
    intel = brewpatch.parse(FORMULA, arch="x86_64")
    assert intel["ids"] == p["ids"] | {"CVE-2026-1004"}  # the other arch's block counts on its own arch


def test_on_linux_only_patch_is_not_credited() -> None:
    p = brewpatch.parse(FORMULA, arch="arm64")
    assert "CVE-2026-1002" not in p["ids"] and "dddddddd44444444" not in p["shas"]
    assert "CVE-2026-1003" not in p["ids"]  # nor a head-only one


def test_comment_run_must_touch_the_patch() -> None:
    text = ('class Foo < Formula\n  # https://github.com/foo/foo/commit/1234567890abcdef\n\n'
            '  patch do\n    file "Patches/foo/fix.patch"\n  end\nend\n')
    assert brewpatch.parse(text, arch="arm64") == {"ids": set(), "shas": set()}


@pytest.mark.parametrize("text", [
    "class Foo < Formula\n  patch do\n    resolves \"CVE-2026-1\"\n",  # never closed
    "class Foo < Formula\nend\nend\n",  # one end too many
    "class Foo < Formula\n  def install\n    x = <<~EOS\n      never ends\n",  # heredoc runs out
])
def test_what_it_cannot_parse_is_unknown_not_empty(text: str) -> None:
    assert brewpatch.parse(text, arch="arm64") is None


def test_unreadable_or_missing_formula_is_unknown(tmp_path: Path) -> None:
    item = keg(tmp_path)
    assert brewpatch.read(item) is not None
    (Path(item["path"]) / ".brew" / "libssh2.rb").unlink()
    assert brewpatch.read(item) is None
    assert brewpatch.read({"path": None, "name": "x"}) is None


def test_prefix_sha_match_either_direction_and_case() -> None:
    patches = {"ids": set(), "shas": {"2dae3024897e1898d389835151f4e9606227721d"}}
    adv = {"advisory": "X-1", "ids": ["X-1"]}
    assert brewpatch.matches(dict(adv, fix_commits=["2DAE302"]), patches)  # short fix, long patch sha
    long = {"ids": set(), "shas": {"2dae3024"}}
    assert brewpatch.matches(dict(adv, fix_commits=["2dae3024897e1898d389835151f4e9606227721d"]), long)
    assert not brewpatch.matches(dict(adv, fix_commits=["2dae30"]), patches)  # under 7 hex: no claim
    assert not brewpatch.matches(dict(adv, fix_commits=["2dae3025"]), patches)
    assert brewpatch.matches({"advisory": "CVE-1", "ids": ["cve-2026-9"]}, {"ids": {"CVE-2026-9"}, "shas": set()})


# --- osv.match records the fix commits ---------------------------------------

def test_fix_commits_read_events_and_extracted_events() -> None:
    assert osv.fix_commits(RECORDS["OSV-2025-90"], REPO) == ["631e2f82a32ef016299ebb1af66efeae0161f68e"]
    assert osv.fix_commits(RECORDS["CVE-2025-15661"], REPO) == ["2dae3024897e1898d389835151f4e9606227721d"]
    assert osv.fix_commits(RECORDS["CVE-2026-58050"], REPO) == []  # last_affected only
    assert osv.fix_commits(RECORDS["OSV-2025-90"], "https://github.com/other/repo") == []
    rec = {"affected": [{"ranges": [{"type": "GIT", "repo": REPO, "events": [{"fixed": "1.2.3"}],
                                     "database_specific": {"extracted_events": [
                                         {"range": [{"fixed": "ABCDEF1234"}, {"fixed": "abcdef1234"}]}]}}]}]}
    assert osv.fix_commits(rec, REPO) == ["abcdef1234"]  # releases are not commits; unique, lower case


# --- end to end: match -> mark -> render ------------------------------------

def test_libssh2_end_to_end(tmp_path: Path, osv_stub: None) -> None:
    items = [keg(tmp_path)]
    osv.match(items, set())
    advs = {a["advisory"]: a for a in items[0]["advisories"]}
    assert set(advs) == set(RECORDS)
    assert all(a["patched_by_brew"] == "unknown" and a["fixed"] is None for a in advs.values())

    brewpatch.mark(items, arch="arm64")
    marks = {k: a["patched_by_brew"] for k, a in advs.items()}
    assert [k for k, v in marks.items() if v == "true"] == sorted(set(RECORDS) - {NO_FIX})
    assert marks[NO_FIX] == "false"
    assert all(advs[k]["fix_commits"] == [] for k in BY_ID)  # so these matched by id
    for k in BY_EVENTS:  # these matched by commits OSV holds in plain `events` only
        assert advs[k]["fix_commits"]
        assert brewpatch.matches({"advisory": "-", "ids": [], "fix_commits": advs[k]["fix_commits"]},
                                 brewpatch.read(items[0], arch="arm64"))
    assert items[0]["status"] == "exposed"  # one advisory is not brew-patched

    prom = export.render(scan_of(items), detail=True)
    detail = lines(prom, "patched_advisory_exposed")
    assert len(detail) == 15  # nothing silently vanishes
    assert sum('patched_by_brew="true"' in ln for ln in detail) == 14
    (no_fix,) = [ln for ln in detail if NO_FIX in ln]
    assert 'patch="none"' in no_fix and 'patched_by_brew="false"' in no_fix and 'fix_commit=""' in no_fix
    (cve,) = [ln for ln in detail if '"CVE-2025-15661"' in ln]
    assert 'patch="commit"' in cve and 'fix_commit="2dae3024897e"' in cve
    # exposed: only OSV-2025-433 (severity unknown, no fix); 14 counted as brew-patched
    exposed = {ln.rsplit(" ", 1)[0]: int(ln.rsplit(" ", 1)[1]) for ln in lines(prom, "patched_exposed")}
    assert sum(exposed.values()) == 1
    assert exposed[f'patched_exposed{{severity="{advs[NO_FIX]["severity"]}",kev="false",patch="none",in_use="true"}}'] == 1
    brewed = lines(prom, "patched_brew_patched")
    assert len(brewed) == len(export.SEVERITIES) * 2 * 2  # the whole zero grid
    assert sum(int(ln.rsplit(" ", 1)[1]) for ln in brewed) == 14

    listener = {"process": "x", "port": "22", "bind": "any", "paths": [items[0]["path"] + "lib/libssh2.dylib"]}
    collect.link([listener], items)
    assert listener["exposed"] and not listener["kev"]  # OSV-2025-433 still exposes it


def test_all_brew_patched_item_is_patched_not_exposed(tmp_path: Path, osv_stub: None, monkeypatch) -> None:
    monkeypatch.setattr(osv, "_batch", lambda qs: [[{"id": i, "modified": r["modified"]}
                                                    for i, r in RECORDS.items() if i != NO_FIX] for _ in qs])
    items = [keg(tmp_path)]
    osv.match(items, set())
    brewpatch.mark(items, arch="arm64")
    assert items[0]["status"] == "patched"
    listener = {"process": "x", "port": "22", "bind": "any", "paths": [items[0]["path"] + "lib/x"]}
    collect.link([listener], items)
    assert not listener["exposed"]
    prom = export.render(scan_of(items))
    assert all(ln.endswith(" 0") for ln in lines(prom, "patched_exposed"))
    s = scan_of(items)
    assert "1 patched by brew (14 advisories brew-patched)" in cli.summary(s)
    assert "0 exposed (0 advisories, 0 known exploited)" in cli.summary(s)


def test_unreadable_formula_leaves_all_unknown_and_exposed(tmp_path: Path, osv_stub: None) -> None:
    items = [keg(tmp_path, text="class Libssh2 < Formula\n  patch do\n")]  # cannot parse
    osv.match(items, set())
    brewpatch.mark(items, arch="arm64")
    assert {a["patched_by_brew"] for a in items[0]["advisories"]} == {"unknown"}
    assert items[0]["status"] == "exposed"
    prom = export.render(scan_of(items))
    assert sum(int(ln.rsplit(" ", 1)[1]) for ln in lines(prom, "patched_exposed")) == 15
    assert sum(int(ln.rsplit(" ", 1)[1]) for ln in lines(prom, "patched_brew_patched")) == 0


def test_a_failed_brew_patches_stage_is_fail_safe(tmp_path: Path, osv_stub: None, monkeypatch) -> None:
    items = [keg(tmp_path)]
    stubs = {
        (collect, "brew"): lambda: (items, set()), (collect, "apps"): lambda casks: [],
        (collect, "uv_tools"): list, (collect, "npm_globals"): list, (collect, "listeners"): list,
        (collect, "launchd"): list, (collect, "protections"): dict, (collect, "macos"): dict,
        (collect, "served_ports"): dict, (scan.kev, "load"): lambda: (set(), None),
        (scan.allow, "services"): lambda host: (None, []), (scan.allow, "products"): lambda host: None,
    }
    for (mod, name), fn in stubs.items():
        monkeypatch.setattr(mod, name, fn)

    def boom(its, arch=None):
        raise RuntimeError("brewpatch broke")
    monkeypatch.setattr(scan.brewpatch, "mark", boom)
    monkeypatch.setattr(scan.allow, "services", lambda host: (None, []))
    monkeypatch.setattr(scan.allow, "products", lambda host: None)
    s = scan.run(update=False)
    assert s["stages"]["osv"] is True and s["stages"]["brew_patches"] is False
    assert {a["patched_by_brew"] for a in items[0]["advisories"]} == {"unknown"}
    prom = export.render(s)
    assert 'patched_scan_ok{stage="brew_patches"} 0' in prom
    assert "patched_brew_patched{" not in prom  # a failed stage claims no zero
    assert sum(int(ln.rsplit(" ", 1)[1]) for ln in lines(prom, "patched_exposed")) == 15


def test_mark_writes_nothing_if_it_fails_part_way(tmp_path: Path, osv_stub: None, monkeypatch) -> None:
    items = [keg(tmp_path), keg(tmp_path / "b")]
    osv.match(items, set())
    calls = []

    def read(item, arch=None):
        calls.append(item)
        if len(calls) == 2:
            raise RuntimeError("second keg broke")
        return {"ids": {"CVE-2025-15661"}, "shas": set()}
    monkeypatch.setattr(brewpatch, "read", read)
    with pytest.raises(RuntimeError):
        brewpatch.mark(items)
    assert {a["patched_by_brew"] for i in items for a in i["advisories"]} == {"unknown"}


def test_non_brew_advisories_are_na() -> None:
    items = [{"source": "uv-tool", "name": "x", "version": "1", "status": "exposed",
              "advisories": [{"advisory": "CVE-1", "ids": ["CVE-1"], "patched_by_brew": "n/a"}]}]
    brewpatch.mark(items)
    assert items[0]["advisories"][0]["patched_by_brew"] == "n/a" and items[0]["status"] == "exposed"


# --- commit-only fixes --------------------------------------------------------

@pytest.mark.parametrize("adv,outdated,want", [
    ({"fixed": "1.2.0", "fix_commits": ["abcdef1"]}, False, "1.2.0"),
    ({"fixed": None, "fix_commits": ["abcdef1"]}, True, "available"),
    ({"fixed": None, "fix_commits": ["abcdef1"]}, False, "commit"),
    ({"fixed": None, "fix_commits": []}, False, "none"),
])
def test_patch_label(adv: dict, outdated: bool, want: str) -> None:
    assert export.patch_label(adv, {"outdated": outdated}) == want


def test_commit_only_advisory_renders_commit_not_none() -> None:
    item = {"source": "uv-tool", "name": "x", "version": "1.0", "in_use": True, "outdated": False,
            "status": "exposed", "advisories": [
                {"advisory": "CVE-2026-2", "severity": "high", "kev": False, "fixed": None,
                 "fix_commits": ["ffff0000aaaa1111bbbb", "0123456789abcdef0123"], "patched_by_brew": "n/a"}]}
    prom = export.render(scan_of([item]), detail=True)
    assert 'patched_exposed{severity="high",kev="false",patch="commit",in_use="true"} 1' in prom
    assert 'patched_exposed{severity="high",kev="false",patch="none",in_use="true"} 0' in prom
    assert 'patch="commit",in_use="true",patched_by_brew="n/a",fix_commit="0123456789ab",fix="commit"} 1' in prom
