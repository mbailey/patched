"""The report: hand-built scans in, what to do out. No network, no real records."""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

import pytest
from click.testing import CliRunner

from patched import export, report, schedule
from patched import scan as scanner
from patched.cli import main

NOW = time.mktime((2026, 11, 20, 14, 25, 0, 0, 0, -1))  # local 14:25
ANSI = re.compile(r"\033\[[0-9;]*m")


def adv(sev: str = "medium", kev: bool = False, fixed: str | None = None, commits: tuple = (),
        brew: str = "n/a", name: str = "GHSA-x") -> dict:
    return {"advisory": name, "severity": sev, "kev": kev, "fixed": fixed, "fix_commits": list(commits),
            "patched_by_brew": brew}


def item(name: str, version: str, *advs: dict, source: str = "brew-formula", **kw) -> dict:
    return {"source": source, "name": name, "version": version,
            "status": "exposed" if advs else kw.pop("status", "clean"), "advisories": list(advs), **kw}


def scan(*items: dict, listeners: tuple = (), osv: bool = True, **extra) -> dict:
    s = {"host": "host1", "started": NOW - 120, "finished": NOW - 110, "stamp": "20261120T142300",
         "stages": {"osv": osv, "brew": True}, "errors": {} if osv else {"osv": "skipped: --offline"},
         "items": list(items), "listeners": list(listeners)}
    return s | extra


def text(s: dict, **kw) -> str:
    return report.render(report.build(s, kw.pop("record", None)), now=NOW, **kw)


def rows(rollup: dict, fix: str) -> list[dict]:
    return next(g for g in rollup["groups"] if g["fix"] == fix)["rows"]


# --- rule 1: the groups ---

def test_groups_are_the_fix_kinds_in_order_with_their_names() -> None:
    s = scan(item("a", "1", adv(fixed="2")), item("b", "1", adv(commits=("c0ffee",))),
             item("c", "1", adv()), item("d", "1_1", adv(brew="true")))
    r = report.build(s)
    assert [g["fix"] for g in r["groups"]] == ["release", "commit", "none", "brew"]
    assert {g["fix"] for g in r["groups"]} == set(export.FIXES)
    out = text(s)
    heads = ["Install now", "Wait for a release  -  fixed upstream, not released yet",
             "No fix known  -  keep it only if you need it", "Already patched by Homebrew  -  nothing to do"]
    at = [out.index(h) for h in heads]
    assert at == sorted(at)


def test_an_item_with_two_kinds_is_in_both_groups_each_with_its_own_count() -> None:
    s = scan(item("libx", "1.0", adv(fixed="1.1"), adv(fixed="1.2"), adv(brew="true"), adv(brew="true"),
                  adv(brew="true"), source="brew-formula"))
    r = report.build(s)
    assert [(x["name"], x["advisories"]) for x in rows(r, "release")] == [("libx", 2)]
    assert [(x["name"], x["advisories"]) for x in rows(r, "brew")] == [("libx", 3)]
    assert rows(r, "release")[0]["fixed"] == "1.2"  # export.install_fixed: the highest
    out = text(s)
    assert "  libx         1.0 -> 1.2          2 advisories" in out
    assert "  libx         1.0                 3 advisories" in out


def test_empty_groups_are_not_printed_but_install_now_always_speaks() -> None:
    out = text(scan(item("w", "1", adv(commits=("c0ffee",)))))
    assert "Nothing to install now." in out
    assert "Install now " not in out and "No fix known" not in out and "Already patched" not in out
    assert "Wait for a release" in out


def test_patch_label_and_install_fixed_are_reused_latest_when_no_version() -> None:
    s = scan(item("httpx", "0.27", adv(), source="uv-tool", outdated=True))
    [row] = rows(report.build(s), "release")
    assert row["fixed"] == "latest"
    assert "  httpx        0.27 -> latest      1 advisory    (uv tool)" in text(s)


# --- rule 2: a row ---

def test_a_row_names_the_worst_severity_critical_or_high_only() -> None:
    s = scan(item("a", "1", adv("high", fixed="2"), adv("high", fixed="2"), adv("medium", fixed="2")),
             item("b", "1", adv("critical", fixed="2"), adv("low", fixed="2")),
             item("c", "1", adv("medium", fixed="2")))
    out = text(s)
    assert re.search(r"^  a +1 -> 2 +3 advisories  2 high$", out, re.MULTILINE)
    assert re.search(r"^  b +1 -> 2 +2 advisories  1 critical$", out, re.MULTILINE)
    assert re.search(r"^  c +1 -> 2 +1 advisory$", out, re.MULTILINE)
    assert "medium" not in out and "low" not in out


def test_flags_known_exploited_listening_not_in_use_and_source() -> None:
    s = scan(item("jq", "1.7", adv("critical", fixed="1.8.1")),
             item("kev", "1", adv("high", True, fixed="2")),
             item("tool", "2", adv(fixed="3"), source="npm-global", in_use=False),
             item("Viewer", "5", adv(), source="brew-cask"),
             listeners=({"process": "jq", "port": "8080", "bind": "any",
                         "items": [["brew-formula", "jq", "1.7"]]},
                        {"process": "jq", "port": "9", "bind": "loopback",
                         "items": [["brew-formula", "jq", "1.7"]]}))
    out = text(s)
    assert re.search(r"^  jq +1.7 -> 1.8.1 +1 advisory    1 critical  listening on \*:8080$", out, re.MULTILINE)
    assert re.search(r"^  kev +1 -> 2 +1 advisory    1 high  KNOWN EXPLOITED$", out, re.MULTILINE)
    assert ":9" not in out  # loopback is not beyond this Mac
    assert re.search(r"^  tool .*1 advisory    \(not in use\)  \(npm\)$", out, re.MULTILINE)
    assert re.search(r"^  Viewer .*1 advisory    \(cask\)$", out, re.MULTILINE)
    assert "(brew-formula)" not in out


def test_a_served_listener_names_its_bind() -> None:
    s = scan(item("web", "1", adv(fixed="2")),
             listeners=({"process": "web", "port": "443", "bind": "served", "items": [["brew-formula", "web", "1"]]},))
    assert "listening on 443 via tailscale serve (tailnet)" in text(s)


@pytest.mark.parametrize("bind,words", [
    ("any", "*:8080"),
    ("address", "8080 on one address"),
    ("served", "8080 via tailscale serve (tailnet)"),
    ("funnel", "8080 via tailscale funnel (internet)"),
    ("someday", "someday:8080"),  # a kind it does not know: as it is
])
def test_each_bind_kind_reads_as_where_it_is_reachable(bind: str, words: str) -> None:
    s = scan(item("web", "1", adv(fixed="2")),
             listeners=({"process": "web", "port": "8080", "bind": bind, "items": [["brew-formula", "web", "1"]]},))
    assert rows(report.build(s), "release")[0]["listening"] == [words]  # --json carries the same words
    assert f"listening on {words}" in text(s)


def test_a_funnel_bind_wraps_under_its_row_within_80_columns() -> None:
    s = scan(item("jq", "1.7", adv("critical", True, fixed="1.8.1")),
             listeners=({"process": "jq", "port": "8080", "bind": "any", "items": [["brew-formula", "jq", "1.7"]]},
                        {"process": "jq", "port": "443", "bind": "funnel", "items": [["brew-formula", "jq", "1.7"]]}))
    lines = text(s).splitlines()
    assert max(len(x) for x in lines) <= 80
    at = next(i for i, x in enumerate(lines) if x.startswith("  jq "))
    assert lines[at].rstrip().endswith("1 advisory    1 critical")
    assert lines[at + 1] == "    KNOWN EXPLOITED  listening on *:8080, 443 via tailscale funnel (internet)"


# --- rule 3: order within a group ---

def test_order_kev_then_listening_then_severity_then_count_then_name() -> None:
    s = scan(item("zz-kev", "1", adv("low", True, fixed="2")),
             item("yy-listen", "1", adv("low", fixed="2")),
             item("aa-many-high", "1", adv("high", fixed="2"), adv("high", fixed="2")),
             item("bb-one-high", "1", adv("high", fixed="2")),
             item("cc-crit", "1", adv("critical", fixed="2")),
             item("ab-one-high", "1", adv("high", fixed="2")),
             listeners=({"process": "y", "port": "1", "bind": "any", "items": [["brew-formula", "yy-listen", "1"]]},))
    assert [r["name"] for r in rows(report.build(s), "release")] == [
        "zz-kev", "yy-listen", "cc-crit", "aa-many-high", "ab-one-high", "bb-one-high"]


# --- rule 4: the commands ---

def test_commands_one_line_per_manager_every_item_uv_one_each() -> None:
    s = scan(item("libssh2", "1", adv(fixed="2")), item("jq", "1", adv(fixed="2")),
             item("Viewer", "1", adv(fixed="2"), source="brew-cask"),
             item("Other", "1", adv(fixed="2"), source="brew-cask"),
             item("httpx", "1", adv(fixed="2"), source="uv-tool"),
             item("ruff", "1", adv(fixed="2"), source="uv-tool"),
             item("wrangler", "1", adv(fixed="2"), source="npm-global"),
             item("@scope/pkg", "1", adv(fixed="2"), source="npm-global"),
             item("Zoom", "1", adv(fixed="2"), source="app"),
             item("waits", "1", adv(commits=("c0ffee",))))
    r = report.build(s)
    assert next(g for g in r["groups"] if g["fix"] == "release")["commands"] == [
        "brew upgrade jq libssh2",
        "brew upgrade --cask Other Viewer",
        "uv tool upgrade httpx",
        "uv tool upgrade ruff",
        "npm install -g @scope/pkg@latest wrangler@latest",
    ]
    out = text(s)
    assert "\n\n  brew upgrade jq libssh2\n  brew upgrade --cask Other Viewer\n" in out
    assert "Zoom" in out and "upgrade Zoom" not in out  # an app has no command
    assert "waits" not in "\n".join(line for line in out.splitlines() if "upgrade" in line)


def test_a_long_command_wraps_with_a_continuation() -> None:
    names = [f"formula-{n:02d}" for n in range(12)]
    out = text(scan(*(item(n, "1", adv(fixed="2")) for n in names)))
    lines = out.splitlines()
    start = lines.index(next(x for x in lines if x.startswith("  brew upgrade ")))
    cmd = []
    for line in lines[start:]:
        cmd.append(line)
        if not line.endswith(" \\"):
            break
    assert len(cmd) > 1 and all(len(x) <= 80 for x in cmd)
    joined = " ".join(x.removesuffix(" \\").strip() for x in cmd)
    assert joined == "brew upgrade " + " ".join(names)


# --- rule 5: coverage always closes ---

def test_coverage_closes_with_the_real_counts() -> None:
    s = scan(item("a", "1", adv(fixed="2")), item("b", "1"), item("c", "1", status="patched"),
             *(item(f"app{n}", "1", status="no_key", source="app") for n in range(3)),
             *(item(f"e{n}", "1", status="empty") for n in range(2)),
             item("g", "1", status="blind"))
    s["items"][2]["status"] = "patched"
    r = report.build(s, "/x/host1-1.json")
    assert r["coverage"] == {"items": 9, "checked": 3, "no_key": 3, "empty": 2, "blind": 1}
    out = text(s, record="/x/host1-1.json")
    flat = " ".join(out.split())
    assert ("Checked 3 of 9 items. No advisory source for the other 6: 3 have no key (casks and apps "
            "are listed, never matched), 2 are unknown to OSV, 1 could not be matched by version.") in flat
    assert out.rstrip().endswith("Record: /x/host1-1.json")


def test_coverage_with_everything_checked_and_the_record_under_home(monkeypatch: pytest.MonkeyPatch,
                                                                    tmp_path: Path) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    out = text(scan(item("a", "1")), record=str(tmp_path / ".patched/scans/host1-1.json"))
    assert "Checked 1 of 1 item.\nRecord: ~/.patched/scans/host1-1.json\n" in out


# --- rule 6: a scan that could not check ---

@pytest.mark.parametrize("reason", ["skipped: --offline", "RuntimeError: osv.dev said 503"])
def test_an_unchecked_scan_says_so_in_place_of_the_groups(reason: str) -> None:
    s = scan(item("a", "1", status=None), item("b", "1", status=None), osv=False)
    s["errors"] = {"osv": reason}
    r = report.build(s)
    assert r["checked"] is False and r["reason"] == reason and r["groups"] == []
    out = text(s)
    assert f"Advisories were not checked ({reason}). Nothing below is a verdict." in " ".join(out.split())
    assert "Nothing to install now" not in out and "Install now" not in out
    assert "Checked 0 of 2 items." in out


# --- rule 7: colour ---

def test_colour_only_when_asked_and_never_the_only_carrier() -> None:
    s = scan(item("jq", "1", adv("critical", True, fixed="2")), item("w", "1", adv(commits=("c0ffee",))))
    plain, painted = text(s), text(s, color=True)
    assert "\033[" not in plain
    assert ANSI.sub("", painted) == plain  # the same words, colour or not
    assert "\033[1mInstall now\033[0m" in painted
    assert "\033[31mKNOWN EXPLOITED\033[0m" in painted and "\033[31m1 critical\033[0m" in painted
    assert "\033[2mfixed upstream, not released yet\033[0m" in painted


def test_the_cli_paints_only_on_a_terminal_without_no_color(monkeypatch: pytest.MonkeyPatch) -> None:
    from patched import cli

    class Tty:
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr(cli.sys, "stdout", Tty())
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert cli._color() is True
    monkeypatch.setenv("NO_COLOR", "1")
    assert cli._color() is False


# --- the header, and width ---

def test_the_header_names_the_host_and_when() -> None:
    assert text(scan()).splitlines()[0] == "patched  host1  scanned today 14:23 (2 min ago)"
    assert report.when(NOW - 86400, NOW).startswith("yesterday 14:25 (24 h ago)")
    assert report.when(NOW - 5 * 86400, NOW).endswith("(5 days ago)")


def test_no_line_passes_80_columns_for_names_up_to_24() -> None:
    long = "n" * 24
    s = scan(item(long, "10.49.1", *[adv("critical", True, fixed="10.50.12")] * 15),
             item(long[:-1] + "b", "2.0", adv("high", fixed="2.1"), source="npm-global", in_use=False),
             item(long[:-1] + "c", "8.30.1", adv(), source="brew-cask", in_use=False),
             item(long[:-1] + "d", "1", adv(commits=("c0ffee",)), source="uv-tool"),
             listeners=tuple({"process": "x", "port": str(p), "bind": "any",
                              "items": [["brew-formula", long, "10.49.1"]]} for p in (8080, 8443, 9090)),
             )
    out = text(s, record="/x/" + "r" * 40 + ".json")
    assert max(len(x) for x in out.splitlines()) <= 80
    lines = out.splitlines()
    first = next(i for i, x in enumerate(lines) if x.startswith("  " + long + " "))
    assert lines[first].rstrip().endswith("15 advisories  15 critical")  # name, versions, count, severity
    assert lines[first + 1].startswith("    KNOWN EXPLOITED  listening on *:8080")  # flags wrap under it


# --- `patched report` ---

def run(*args: str):
    return CliRunner().invoke(main, ["report", *args])


@pytest.fixture
def records(monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(scanner, "host", lambda: "host1")
    return schedule.SCANS_DIR  # under tmp_path (tests/conftest.py)


def test_report_with_no_record_says_run_scan_exit_1(records: Path) -> None:
    r = run()
    assert r.exit_code == 1 and r.output == "no scan yet: run patched scan\n"


def test_report_on_an_unreadable_record_is_one_line_exit_2(records: Path) -> None:
    records.mkdir(parents=True)
    bad = records / "host1-20261120T142300.json"
    bad.write_text("{half")
    r = run()
    assert r.exit_code == 2 and len(r.output.strip().splitlines()) == 1 and str(bad) in r.output
    assert "Traceback" not in r.output


def test_report_reads_the_newest_record_and_json_is_build(records: Path) -> None:
    records.mkdir(parents=True)
    old = scan(item("stale-item", "1", adv(fixed="2")))
    new = scan(item("jq", "1.7", adv("critical", fixed="1.8.1")))
    (records / "host1-20261119T100000.json").write_text(json.dumps(old))
    path = records / "host1-20261120T142300.json"
    path.write_text(json.dumps(new))
    (records / "other-20261121T000000.json").write_text(json.dumps(old))  # another host's: not ours
    r = run("--json")
    assert r.exit_code == 0, r.output
    assert json.loads(r.output) == report.build(new, str(path))
    t = run()
    assert t.exit_code == 0 and "  jq " in t.output and "stale-item" not in t.output
    assert ANSI.sub("", t.output).splitlines()[1:] == report.render(report.build(new, str(path))).splitlines()[1:]


def test_a_listening_flag_too_long_for_one_line_breaks_at_its_commas() -> None:
    binds = (("any", "8080"), ("address", "9090"), ("served", "443"), ("funnel", "8443"))
    s = scan(item("web", "1", adv("high", fixed="2")),
             listeners=tuple({"process": "web", "port": p, "bind": b, "items": [["brew-formula", "web", "1"]]}
                             for b, p in binds))
    out = text(s)
    assert max(len(x) for x in out.splitlines()) <= 80
    flat = " ".join(out.split())
    assert ("listening on *:8080, 9090 on one address, 443 via tailscale serve (tailnet), "
            "8443 via tailscale funnel (internet)") in flat
