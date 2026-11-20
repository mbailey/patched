"""The exporter's call-to-action rollup.

Per item, what to do about its advisories: install a release (and which
one), wait on a commit, nothing (brew patched it), or nothing known. The
version order is osv.vkey's, done here because PromQL has none. Fixtures
only: the libssh2 keg and OSV records from test_brewpatch, plus hand-made
items.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import test_brewpatch as bp

from patched import brewpatch, export, osv


@pytest.fixture
def libssh2(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> list[dict]:
    """A real libssh2 1.11.1_7, matched and marked: 15 advisories, 14 brew-patched."""
    monkeypatch.setattr(osv, "_known", lambda pkgs: dict.fromkeys(pkgs, True))
    monkeypatch.setattr(osv, "_batch", lambda qs: [[{"id": i, "modified": r["modified"]}
                                                    for i, r in bp.RECORDS.items()] for _ in qs])
    monkeypatch.setattr(osv, "_vuln", lambda vid, mod: bp.RECORDS[vid])
    items = [bp.keg(tmp_path)]
    osv.match(items, set())
    brewpatch.mark(items, arch="arm64")
    return items


def values(prom: str, name: str) -> dict[str, int]:
    """{label set: value} for one family."""
    return {ln[len(name):].rsplit(" ", 1)[0]: int(ln.rsplit(" ", 1)[1])
            for ln in prom.splitlines() if ln.startswith((name + "{", name + " "))}


def adv(name: str, severity: str = "medium", kev: bool = False, fixed: str | None = None,
        commits: list[str] | None = None, brew: str = "n/a") -> dict:
    return {"advisory": name, "severity": severity, "kev": kev, "fixed": fixed,
            "fix_commits": commits or [], "patched_by_brew": brew}


def item(advisories: list[dict], name: str = "fileshare", version: str = "1.20.16", source: str = "uv-tool",
         in_use: bool = True, outdated: bool = False) -> dict:
    return {"source": source, "name": name, "version": version, "in_use": in_use, "outdated": outdated,
            "status": "exposed", "advisories": advisories}


# --- one fix kind per advisory -------------------------------------------------

@pytest.mark.parametrize("a,outdated,want", [
    (adv("A", fixed="1.2.0"), False, "release"),
    (adv("A"), True, "release"),  # patch="available": the updater has a newer one
    (adv("A", commits=["abcdef1"]), False, "commit"),
    (adv("A"), False, "none"),
    (adv("A", brew="true"), False, "brew"),  # brew first: patch="none" here (58050/58051)
    (adv("A", commits=["abcdef1"], brew="true"), False, "brew"),
    (adv("A", fixed="1.2.0", brew="true"), False, "brew"),
    (adv("A", brew="false"), False, "none"),
    (adv("A", fixed="1.2.0", brew="unknown"), False, "release"),
])
def test_fix_kind(a: dict, outdated: bool, want: str) -> None:
    assert export.fix_kind(a, {"outdated": outdated}) == want


def test_install_fixed_is_the_highest_by_vkey() -> None:
    assert export.install_fixed(["1.2.9", "1.2.10", "1.2.3"]) == "1.2.10"  # not the string max
    assert export.install_fixed(["2.0.0"]) == "2.0.0"
    assert export.install_fixed(["1.2.10", "available"]) == "latest"


# --- libssh2 -------------------------------------------------------------------

def test_libssh2_rolls_up_to_0_release_14_brew_1_none(libssh2: list[dict]) -> None:
    prom = export.render(bp.scan_of(libssh2), detail=True)
    common = 'source="brew-formula",product="libssh2",version="1.11.1_7",in_use="true"'
    sev = {a["advisory"]: a["severity"] for a in libssh2[0]["advisories"]}
    brewed = export.cvss.worst(*(v for k, v in sev.items() if k != bp.NO_FIX))
    assert values(prom, "patched_install") == {
        f'{{{common},fix="brew",fixed="",severity="{brewed}",kev="false"}}': 14,
        f'{{{common},fix="none",fixed="",severity="{sev[bp.NO_FIX]}",kev="false"}}': 1,
    }  # no release row: nothing to install
    items = values(prom, "patched_install_items")
    assert len(items) == len(export.FIXES) * 2 * 2  # the whole grid, zeros included
    assert items['{fix="release",kev="false",in_use="true"}'] == 0
    assert items['{fix="brew",kev="false",in_use="true"}'] == 1
    assert items['{fix="none",kev="false",in_use="true"}'] == 1
    assert items['{fix="commit",kev="false",in_use="true"}'] == 0
    assert sum(items.values()) == 2
    per_cve = [ln for ln in prom.splitlines() if ln.startswith("patched_advisory_exposed{")]
    for cve in bp.BY_ID:  # patch="none", brew-patched: brew, never "no fix"
        (ln,) = [ln for ln in per_cve if f'"{cve}"' in ln]
        assert 'patch="none"' in ln and ln.endswith(',fix="brew"} 1')
    (ln,) = [ln for ln in per_cve if f'"{bp.NO_FIX}"' in ln]
    assert ln.endswith(',fix="none"} 1')
    assert sum(ln.endswith(',fix="brew"} 1') for ln in per_cve) == 14


# --- a mixed item ----------------------------------------------------------------

def test_mixed_item_highest_fixed_worst_severity_kev() -> None:
    it = item([adv("CVE-1", "low", fixed="1.20.9"), adv("CVE-2", "high", fixed="1.20.17"),
               adv("CVE-3", "medium", kev=True, fixed="1.20.10"),
               adv("CVE-4", "critical", commits=["abcdef1"]), adv("CVE-5", "critical")])
    prom = export.render(bp.scan_of([it]), detail=True)
    base = 'source="uv-tool",product="fileshare",version="1.20.16",in_use="true"'
    assert values(prom, "patched_install") == {
        f'{{{base},fix="commit",fixed="",severity="critical",kev="false"}}': 1,
        f'{{{base},fix="none",fixed="",severity="critical",kev="false"}}': 1,
        f'{{{base},fix="release",fixed="1.20.17",severity="high",kev="true"}}': 3,  # one install clears all 3
    }
    items = values(prom, "patched_install_items")
    assert items['{fix="release",kev="true",in_use="true"}'] == 1
    assert items['{fix="release",kev="false",in_use="true"}'] == 0
    assert items['{fix="commit",kev="false",in_use="true"}'] == 1
    assert items['{fix="none",kev="false",in_use="true"}'] == 1
    assert sum(items.values()) == 3  # one item, counted once in each kind it has


def test_any_available_reads_latest() -> None:
    it = item([adv("CVE-1", fixed="1.20.17"), adv("CVE-2")], outdated=True)  # CVE-2: patch="available"
    prom = export.render(bp.scan_of([it]), detail=True)
    (key,) = values(prom, "patched_install")
    assert 'fix="release",fixed="latest"' in key


def test_unused_copy_counts_apart_and_items_count_per_copy() -> None:
    a = adv("CVE-9", "critical", kev=True, fixed="3.6.5")
    used = item([a], name="openssl@3", version="3.6.4", source="brew-formula")
    unused = item([a], name="openssl@3", version="3.5.9", source="brew-formula", in_use=False)
    prom = export.render(bp.scan_of([used, unused]), detail=False)
    items = values(prom, "patched_install_items")
    assert items['{fix="release",kev="true",in_use="true"}'] == 1  # the call to action
    assert items['{fix="release",kev="true",in_use="false"}'] == 1  # evict, not install
    twin = export.render(bp.scan_of([used, dict(used)]), detail=True)  # two copies, one label set
    assert values(twin, "patched_install_items")['{fix="release",kev="true",in_use="true"}'] == 2
    (n,) = values(twin, "patched_install").values()  # one series, never a duplicate
    assert n == 2


# --- names off, and the stages -----------------------------------------------------

def test_names_off_names_nothing_and_says_so() -> None:
    it = item([adv("CVE-2026-70657", fixed="1.20.17")])
    prom = export.render(bp.scan_of([it]), detail=False)
    for named in ("patched_install{", "patched_advisory_exposed", "fileshare", "1.20.16", "1.20.17",
                  "CVE-2026-70657"):
        assert named not in prom, named
    assert "patched_detail_series 0" in prom.splitlines()
    assert values(prom, "patched_install_items")['{fix="release",kev="false",in_use="true"}'] == 1
    on = export.render(bp.scan_of([it]), detail=True)
    assert "patched_detail_series 1" in on.splitlines()


def test_a_clean_scan_writes_the_zero_grid() -> None:
    prom = export.render(bp.scan_of([]), detail=False)
    items = values(prom, "patched_install_items")
    assert len(items) == 16 and set(items.values()) == {0}  # "nothing to install" is a written 0


def test_failed_osv_claims_no_zero() -> None:
    it = item([adv("CVE-1", fixed="1.20.17")])
    prom = export.render(bp.scan_of([it], osv=False), detail=True)
    assert "patched_install_items{" not in prom and "patched_install{" not in prom
    assert "patched_detail_series 1" in prom.splitlines()


@pytest.mark.parametrize("stages", [{"brew_patches": False}, {"brew": False}])
def test_brew_rows_only_when_brew_patches_counted(stages: dict) -> None:
    it = item([adv("CVE-1", fixed="1.20.17")])
    prom = export.render(bp.scan_of([it], **stages), detail=False)
    items = values(prom, "patched_install_items")
    assert len(items) == 12 and not any('fix="brew"' in k for k in items)
    assert items['{fix="release",kev="false",in_use="true"}'] == 1


def test_every_new_family_has_help() -> None:
    for name in ("patched_install", "patched_install_items", "patched_detail_series"):
        assert name in export.HELP
    assert export.HELP["patched_install"].startswith("DETAIL:")
    assert not export.HELP["patched_install_items"].startswith("DETAIL:")
