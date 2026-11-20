"""Unit tests: no network, no real system state."""
from __future__ import annotations

from pathlib import Path

import pytest

from patched import collect, cvss, export, osv


def test_cvss_v3_scores() -> None:
    assert cvss.v3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert cvss.v3_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H") == 6.5
    assert cvss.v3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1
    assert cvss.v3_score("garbage") is None


def test_severity_prefers_the_advisorys_word() -> None:
    rec = {"database_specific": {"severity": "MODERATE"},
           "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
    assert cvss.severity(rec) == "medium"
    assert cvss.severity({"severity": rec["severity"]}) == "critical"
    assert cvss.severity({}) == "unknown"
    assert cvss.worst("low", "unknown", "high") == "high"


def test_bind_and_process_names() -> None:
    assert collect.bind_of("*") == "any"
    assert collect.bind_of("127.0.0.1") == "loopback"
    assert collect.bind_of("[::1]") == "loopback"
    assert collect.bind_of("192.168.1.5") == "address"
    assert collect.process_name("python3.13", "/x/bin/python /h/webapp/webapp.py --host 0.0.0.0") == "webapp"
    assert collect.process_name("Python", "/x/python -m http.server 8000") == "http.server"
    assert collect.process_name("rapportd", "") == "rapportd"


def test_versions_and_repos() -> None:
    assert collect.strip_revision("1.11.1_7") == "1.11.1"
    assert collect.strip_revision("3.7c") == "3.7c"
    assert collect.github_repo([None, "https://github.com/git/git.git", "x"]) == "https://github.com/git/git"
    assert collect.github_repo(["https://example.org/a.tgz"]) is None
    assert osv.vkey("1.20.17") > osv.vkey("1.20.9")


def test_uv_tools_local_vs_pypi(tmp_path: Path) -> None:
    for name, req in (("fileshare", '{ name = "fileshare" }'),
                      ("mytool", '{ name = "mytool", editable = "/src/mytool" }')):
        (tmp_path / name).mkdir()
        (tmp_path / name / "uv-receipt.toml").write_text(
            f"[tool]\nrequirements = [{req}]\nentrypoints = [\n"
            f'    {{ name = "{name}", install-path = "/b/{name}", from = "{name}" }},\n]\n')
    listing = "fileshare v1.20.16\n- fileshare\nmytool v0.1.0\n- mytool\n- other-tool\n"
    items = {i["name"]: i for i in collect.uv_tools(listing, tmp_path)}
    assert set(items) == {"fileshare", "mytool"}
    assert items["fileshare"]["key"] == ["PyPI", "fileshare", "1.20.16"]
    assert items["mytool"]["key"] is None


def test_brew_in_use_follows_the_opt_link(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "Cellar/openssl@3/3.5.9").mkdir(parents=True)
    (tmp_path / "opt").mkdir()
    (tmp_path / "opt/openssl@3").symlink_to(tmp_path / "Cellar/openssl@3/3.5.9")
    monkeypatch.setattr(collect, "BREW", tmp_path)
    info = {"formulae": [{"name": "openssl@3", "keg_only": True, "outdated": False, "homepage": "",
                          "urls": {"stable": {"url": "https://github.com/openssl/openssl/releases/x.tgz"}},
                          "installed": [{"version": "3.6.4"}, {"version": "3.5.9"}]}],
            "casks": [{"token": "firefox", "installed": "159.0", "auto_updates": True,
                       "artifacts": [{"app": ["Firefox.app"]}]}]}
    items, apps = collect.brew(info)
    use = {i["version"]: i["in_use"] for i in items if i["source"] == "brew-formula"}
    assert use == {"3.6.4": False, "3.5.9": True}
    assert items[0]["key"] == ["GIT", "https://github.com/openssl/openssl", "3.6.4"]
    assert apps == {"Firefox.app"}


def test_group_merges_aliases() -> None:
    recs = [{"id": "CURL-CVE-2026-1", "aliases": ["CVE-2026-1"]}, {"id": "CVE-2026-1"},
            {"id": "GHSA-xxxx", "aliases": []}]
    g = osv.group(recs)
    assert sorted(g) == ["CVE-2026-1", "GHSA-xxxx"]
    assert len(g["CVE-2026-1"]) == 2


def test_fixed_version_for_git_and_pypi() -> None:
    repo = "https://github.com/openssl/openssl"
    git = {"affected": [{"ranges": [
        {"type": "GIT", "repo": repo + ".git", "events": [{"fixed": "abc1234def"}],
         "database_specific": {"extracted_events": [{"range": [{"introduced": "3.6.0"}, {"fixed": "3.6.5"}]}]}},
        {"type": "GIT", "repo": "https://github.com/other/x", "events": [],
         "database_specific": {"extracted_events": [{"range": [{"fixed": "3.6.4.1"}]}]}}]}]}
    assert osv.fixed_version(git, ["GIT", repo, "3.6.4"]) == "3.6.5"
    pypi = {"affected": [{"package": {"name": "fileshare", "ecosystem": "PyPI"},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.20.17"}]}]}]}
    assert osv.fixed_version(pypi, ["PyPI", "fileshare", "1.20.16"]) == "1.20.17"
    assert osv.fixed_version(pypi, ["PyPI", "fileshare", "1.20.17"]) is None


def test_blind_needs_a_tag_list_for_this_repo() -> None:
    repo = "https://github.com/a/b"
    tagged = {"affected": [{"versions": ["v1.0"], "ranges": [{"type": "GIT", "repo": repo}]}]}
    other = {"affected": [{"versions": ["v1.0"], "ranges": [{"type": "GIT", "repo": "https://github.com/c/d"}]}]}
    assert osv.is_blind([other], repo)
    assert not osv.is_blind([other, tagged], repo)


def _scan(osv_ok: bool) -> dict:
    item = {"source": "uv-tool", "name": "fileshare", "version": "1.20.16", "in_use": True,
            "outdated": False, "status": "exposed",
            "advisories": [{"advisory": "CVE-2026-70657", "severity": "medium", "kev": False, "fixed": "1.20.17"}]}
    return {"started": 100.0, "finished": 110.5, "stages": {"osv": osv_ok, "brew": True, "apps": True, "uv": True, "npm": True,
                                                    "listeners": True, "launchd": True},
            "items": [item, {"source": "app", "name": 'Odd "App"', "version": "1", "status": "no_key"}],
            "listeners": [{"process": "webapp", "port": "9000", "bind": "any"}],
            "launchd": [{"scope": "user", "always": True}], "protections": {"firewall": 0},
            "macos": {"version": "27.0.1", "build": "26A434"}, "kev": {"version": "2026.10.27", "count": 1760}}


def test_render_contract() -> None:
    scan = _scan(True)
    scan["items"].append({"source": "brew-formula", "name": "openssl@3", "version": "3.6.4", "in_use": False,
                          "status": "clean", "advisories": []})
    prom = export.render(scan, detail=True)
    assert 'patched_item_unused{source="brew-formula",product="openssl@3",version="3.6.4"} 1' in prom
    assert 'patched_items_unused{source="brew-formula"} 1' in prom
    assert 'patched_advisory_exposed{advisory="CVE-2026-70657",product="fileshare",version="1.20.16",' in prom
    assert 'patch="1.20.17",in_use="true",patched_by_brew="n/a",fix_commit="",fix="release"} 1' in prom
    assert 'patched_exposed{severity="medium",kev="false",patch="available",in_use="true"} 1' in prom
    assert 'patched_exposed{severity="medium",kev="false",patch="commit",in_use="true"} 0' in prom
    assert "patched_brew_patched{" not in prom  # no brew_patches stage ran: no count claims 0
    assert 'patched_items_unmatched{source="app",reason="no_key"} 1' in prom
    assert 'patched_listener{process="webapp",port="9000",bind="any"} 1' in prom
    assert 'patched_listening{bind="any"} 1' in prom
    assert "patched_listening_unallowed 1" in prom
    assert 'patched_allowlist_loaded{list="services"} 0' in prom
    assert 'patched_protection{check="firewall"} 0' in prom
    assert "patched_scan_duration_seconds 10.5" in prom
    assert prom.count("# TYPE patched_items gauge") == 1


def test_render_says_error_not_zero_when_osv_fails() -> None:
    prom = export.render(_scan(False))
    assert 'reason="error"' in prom
    assert "patched_exposed{" not in prom
    assert 'patched_scan_ok{stage="osv"} 0' in prom


def test_write_prom_is_atomic(tmp_path: Path) -> None:
    path = export.write_prom("a 1\n", tmp_path)
    assert path.read_text() == "a 1\n"
    assert [p.name for p in tmp_path.iterdir()] == ["patched.prom"]
    assert oct(path.stat().st_mode & 0o777) == "0o644"


def test_counts_only_by_default() -> None:
    scan = _scan(True)
    scan["items"].append({"source": "brew-formula", "name": "openssl@3", "version": "3.6.4", "in_use": False})
    prom = export.render(scan, detail=False)
    for named in ("patched_advisory_exposed", "patched_item_unused{", "patched_listener{", "webapp",
                  "fileshare", "openssl", "patched_macos_info"):
        assert named not in prom, named
    assert 'patched_items_unused{source="brew-formula"} 1' in prom
    assert 'patched_exposed{severity="medium",kev="false",patch="available",in_use="true"} 1' in prom


def test_fast_path_kev_counts_and_unused_stays_separate() -> None:
    scan = _scan(True)
    kev = {"advisory": "CVE-2026-1", "severity": "critical", "kev": True, "fixed": None}
    scan["items"] += [
        {"source": "brew-formula", "name": "openssl@3", "version": "3.5.9", "in_use": True,
         "outdated": False, "status": "exposed", "advisories": [kev]},
        {"source": "brew-formula", "name": "openssl@3", "version": "3.6.4", "in_use": False,
         "outdated": False, "status": "exposed", "advisories": [kev]},
    ]
    prom = export.render(scan, detail=False)
    assert 'patched_exposed{severity="critical",kev="true",patch="none",in_use="true"} 1' in prom
    assert 'patched_exposed{severity="critical",kev="true",patch="none",in_use="false"} 1' in prom
    detail = export.render(scan, detail=True)
    assert detail.count('advisory="CVE-2026-1"') == 2
    assert 'version="3.6.4",source="brew-formula",severity="critical",kev="true",patch="none",in_use="false"' in detail


def test_kev_join_reads_aliases(monkeypatch) -> None:
    rec = {"id": "GHSA-aaaa", "aliases": ["CVE-2026-9"], "modified": "m",
           "affected": [{"package": {"name": "x", "ecosystem": "PyPI"},
                         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}]}]}
    monkeypatch.setattr(osv, "_known", lambda pkgs: dict.fromkeys(pkgs, True))
    monkeypatch.setattr(osv, "_batch", lambda qs: [[{"id": "GHSA-aaaa", "modified": "m"}] for _ in qs])
    monkeypatch.setattr(osv, "_vuln", lambda vid, mod: rec)
    items = [{"source": "uv-tool", "name": "x", "version": "1.0", "key": ["PyPI", "x", "1.0"]}]
    osv.match(items, {"CVE-2026-9"})
    a = items[0]["advisories"][0]
    assert (items[0]["status"], a["advisory"], a["kev"], a["fixed"]) == ("exposed", "CVE-2026-9", True, "2.0")


def test_link_listener_to_items_and_fast_path_count() -> None:
    items = [
        {"source": "uv-tool", "name": "fileshare", "version": "1.20.16", "in_use": True,
         "path": "/u/tools/fileshare/", "advisories": [{"advisory": "CVE-1", "kev": False}]},
        {"source": "brew-formula", "name": "iperf3", "version": "3.21_1", "in_use": False,
         "path": "/b/Cellar/iperf3/3.21_1/", "advisories": [{"advisory": "CVE-2", "kev": True}]},
        {"source": "brew-formula", "name": "iperf3", "version": "3.22", "in_use": True,
         "path": "/b/Cellar/iperf3/3.22/", "advisories": []},
    ]
    paths = collect.program_paths("/u/tools/fileshare/bin/python", "/u/tools/fileshare/bin/python /x/fileshare -p 1")
    listeners = [{"process": "fileshare", "port": "8000", "bind": "loopback", "paths": sorted(paths)},
                 {"process": "iperf3", "port": "5201", "bind": "any", "paths": ["/b/Cellar/iperf3/3.22/bin/iperf3"]}]
    collect.link(listeners, items)
    assert listeners[0]["items"] == [["uv-tool", "fileshare", "1.20.16"]]
    assert listeners[0]["exposed"] and not listeners[0]["kev"]
    assert listeners[1]["items"] == [["brew-formula", "iperf3", "3.22"]]
    assert not listeners[1]["exposed"]
    scan = _scan(True)
    scan["stages"]["link"] = True
    scan["listeners"] = listeners
    prom = export.render(scan)
    assert 'patched_exposed_listening{bind="loopback",kev="false"} 1' in prom
    assert 'patched_exposed_listening{bind="any",kev="false"} 0' in prom


def test_served_ports_and_bind() -> None:
    status = {"TCP": {"443": {"HTTPS": True}, "465": {"TCPForward": "127.0.0.1:1587"}},
              "Web": {"host1.example.ts.net:443": {"Handlers": {"/files": {"Proxy": "http://127.0.0.1:8000/files"},
                                                       "/x": {"Proxy": "http://127.0.0.1:8790"}}},
                      "host1.example.ts.net:8443": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:8800"}}}},
              "AllowFunnel": {"host1.example.ts.net:8443": True}}
    ports = collect.served_ports(status)
    assert ports == {"1587": "served", "8000": "served", "8790": "served", "8800": "funnel"}
    listeners = [{"process": "fileshare", "port": "8000", "bind": "loopback", "paths": []},
                 {"process": "dovecot", "port": "9993", "bind": "loopback", "paths": []}]
    collect.link(listeners, [], ports)
    assert [li["bind"] for li in listeners] == ["served", "loopback"]


def test_stamp_compares_to_the_microsecond() -> None:
    # The same edit, as the record and as querybatch give it.
    assert osv.stamp("2026-10-15T20:30:08.635811757Z") == osv.stamp("2026-10-15T20:30:08.635811Z")
    assert osv.stamp("2026-10-15T20:30:08.6358Z") == osv.stamp("2026-10-15T20:30:08.635800001Z")
    assert osv.stamp("2026-10-15T20:30:08Z") == osv.stamp("2026-10-15T20:30:08.000000Z")
    assert osv.stamp("2026-10-15T20:30:08.635811Z") != osv.stamp("2026-10-15T20:30:08.635812Z")


def test_vuln_cache_hits_across_precision(tmp_path: Path, monkeypatch) -> None:
    import json

    from patched import net
    monkeypatch.setattr(net, "cache_dir", lambda *parts: tmp_path)
    (tmp_path / "GHSA-aaaa.json").write_text(json.dumps(
        {"id": "GHSA-aaaa", "modified": "2026-10-15T20:30:08.635811757Z"}))

    def no_network(url: str) -> dict:
        raise AssertionError(f"fetched {url}")
    monkeypatch.setattr(net, "get_json", no_network)
    assert osv._vuln("GHSA-aaaa", "2026-10-15T20:30:08.635811Z")["id"] == "GHSA-aaaa"
    monkeypatch.setattr(net, "get_json", lambda url: {"id": "GHSA-aaaa", "modified": "new"})
    assert osv._vuln("GHSA-aaaa", "2026-10-16T00:00:00.000001Z")["modified"] == "new"


def test_a_zero_is_written_so_a_count_can_fall_to_it() -> None:
    # A count that falls to 0 must write the 0, or the board keeps showing the stale count.
    keg = {"source": "brew-formula", "name": "fzf", "version": "0.74.4", "in_use": False, "status": "clean"}
    live = dict(keg, version="0.74.5", in_use=True)
    before, after = _scan(True), _scan(True)
    before["items"] += [keg, dict(keg, name="pcre2"), dict(keg, name="iperf3"), live]
    after["items"] += [live]
    assert 'patched_items_unused{source="brew-formula"} 3' in export.render(before)
    prom = export.render(after)
    assert 'patched_items_unused{source="brew-formula"} 0' in prom
    assert 'patched_items_outdated{source="brew-formula"} 0' in prom
    assert 'patched_exposed{severity="critical",kev="true",patch="none",in_use="true"} 0' in prom
    assert 'patched_listening{bind="funnel"} 0' in prom
    assert 'patched_items_unmatched{source="npm-global",reason="blind"} 0' in prom


def test_a_failed_stage_claims_no_zero() -> None:
    scan = _scan(True)
    scan["stages"].update(npm=False, listeners=False)
    prom = export.render(scan)
    assert 'source="npm-global"' not in prom
    assert "patched_listening{" not in prom


def _products_scan(**stages: bool) -> dict:
    scan = _scan(True)
    scan["stages"].update({"products": True, **stages})
    scan["allow"] = {"products": {
        "loaded": True, "errors": ["fleet/Brewfile:9: not a plain Brewfile entry: 'if x'"], "riding": ["d"],
        "unallowed": {"brew-formula": ["c"], "brew-cask": [], "uv-tool": ["foo", "comms"],
                      "npm-global": ["@acme/spec"], "app": []}}}
    return scan


def test_products_counts_with_zeros_and_detail_names() -> None:
    prom = export.render(_products_scan(), detail=True)
    for line in ('patched_items_unallowed{source="brew-formula"} 1', 'patched_items_unallowed{source="brew-cask"} 0',
                 'patched_items_unallowed{source="uv-tool"} 2', 'patched_items_unallowed{source="npm-global"} 1',
                 'patched_items_unallowed{source="app"} 0', 'patched_allowlist_loaded{list="products"} 1',
                 'patched_allowlist_loaded{list="services"} 0', 'patched_allowlist_errors{list="products"} 1',
                 'patched_unallowed_item{source="uv-tool",name="comms"} 1',
                 'patched_unallowed_item{source="npm-global",name="@acme/spec"} 1',
                 'patched_scan_ok{stage="products"} 1'):
        assert line in prom, line
    assert 'name="d"' not in prom  # a rider is never named
    assert prom.count("# TYPE patched_allowlist_loaded gauge") == 1


def test_products_names_only_with_detail() -> None:
    prom = export.render(_products_scan(), detail=False)
    assert "patched_unallowed_item" not in prom and "comms" not in prom
    assert 'patched_items_unallowed{source="uv-tool"} 2' in prom


def test_products_claim_nothing_when_a_stage_failed() -> None:
    prom = export.render(_products_scan(products=False))
    assert 'patched_scan_ok{stage="products"} 0' in prom
    assert "patched_items_unallowed" not in prom and 'list="products"' not in prom
    prom = export.render(_products_scan(npm=False), detail=True)  # no npm list: no npm count, not 0
    assert 'source="npm-global"' not in prom
    assert 'patched_items_unallowed{source="uv-tool"} 2' in prom


def test_apps_need_brew_too() -> None:
    """With brew failed, a cask's app reads as hand-installed: claim no app count."""
    scan = _products_scan(brew=False)
    scan["allow"]["products"]["unallowed"]["app"] = ["Ghostty", "Zoom"]
    prom = export.render(scan, detail=True)
    assert 'source="app"' not in prom and 'source="brew-formula"' not in prom
    assert 'patched_items_unallowed{source="uv-tool"} 2' in prom
    assert 'patched_items_unallowed{source="app"} 0' in export.render(_products_scan())  # brew worked: a real 0


def test_osv_and_brew_failed_claim_no_app_error_count() -> None:
    """The error count follows the same rule: no brew, no app count."""
    scan = _scan(False)
    scan["stages"]["brew"] = False
    prom = export.render(scan)
    assert 'source="app"' not in prom
    assert 'patched_items_unmatched{source="uv-tool",reason="error"} 1' in prom


def test_allowlist_keys_on_process_and_bind(tmp_path: Path) -> None:
    f = tmp_path / "services"
    f.write_text("# header\nrapportd any  # Continuity (49152)\n\nfileshare served # file server\n")
    entries = collect.allowlist(f)
    assert entries == [{"process": "rapportd", "bind": "any", "why": "Continuity (49152)"},
                       {"process": "fileshare", "bind": "served", "why": "file server"}]
    lis = [{"process": "rapportd", "bind": "any", "port": "58276"},  # a new port: still allowed
           {"process": "rapportd", "bind": "address", "port": "1"},
           {"process": "x", "bind": "loopback", "port": "2"}]
    collect.allow(lis, entries)
    assert [li["allowed"] for li in lis] == [True, False, True]
    assert collect.allowlist(tmp_path / "missing") is None
    f.write_text("rapportd\n")
    with pytest.raises(ValueError, match="services:1"):
        collect.allowlist(f)
