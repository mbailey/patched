"""The board's call to action, grafana/patched.json.

Two halves. The JSON's structure: the "Install now" band sits at y=0, every
expr names a series the exporter writes, the four fix kinds read apart, and
every pre-existing panel is kept. And the exprs themselves, evaluated by
promtool on series rendered from fixture scans (names on, names off, nothing
to install, missing): promtool is a local evaluator, no server and no port.
It cannot render a value mapping, so "Nothing to install" is checked as two
facts: the expr gives 0, and the panel maps 0 to that text; "unknown" is the
expr giving no sample, and the panel's noValue saying so.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import test_brewpatch as bp
from test_install import adv, item

from patched import export

BOARD = Path(__file__).resolve().parents[1] / "grafana" / "patched.json"
DOC = json.loads(BOARD.read_text())
PANELS = {p["id"]: p for p in DOC["panels"]}
BY_TITLE = {p["title"]: p for p in DOC["panels"]}
BAND_ROW = 23
OVERVIEW_ROW = 31
STATS = ("To install", "Names", "Fixed upstream, no release", "Brew already patched", "No fix known")
TABLES = ("Install now", "Exposed, by product (counts)")
# The Overview and Detail panels, id -> title, in their (y, x) order: every one is kept.
KEPT = {20: "Patched alerts, firing and pending (Prometheus)", 1: "Known exploited", 2: "Critical exposed",
        3: "Exposed, no patch", 4: "Listening beyond loopback", 5: "Blind spots", 6: "Last scan",
        7: "Protections", 8: "Exposed over time, by severity", 9: "Installed, outdated and unmatched, by source",
        10: "Exposed, by severity and patch (counts)", 11: "Listeners not on the allow list",
        15: "Exposed and listening", 21: "Installed, not allowed",
        13: "Unused copies: evict", 14: "Scan stages failing",
        16: "Detail: names (empty unless patched runs with --detail)", 17: "Exposed advisories, by product",
        18: "Listeners", 19: "Unused copies, by name: evict", 22: "Installed, not allowed, by name"}
# Not the exporter's, and named on purpose: node_exporter's mtime and Prometheus's ALERTS.
OTHERS = {"ALERTS", "node_textfile_mtime_seconds"}
PROMQL_WORDS = {"by", "without", "on", "ignoring", "group_left", "group_right", "and", "or", "unless", "bool",
                "offset"}


def pos(p: dict) -> tuple[int, int]:
    return p["gridPos"]["y"], p["gridPos"]["x"]


def exprs() -> list[str]:
    out = [t["expr"] for p in DOC["panels"] for t in p.get("targets", [])]
    return out + [v["query"]["query"] for v in DOC["templating"]["list"]]


def metrics(expr: str) -> set[str]:
    """The series an expr reads: strings, matchers and grouping lists dropped, functions skipped."""
    bare = re.sub(r'"(?:[^"\\]|\\.)*"', '""', expr)
    bare = re.sub(r"\{[^}]*\}", " ", bare)
    bare = re.sub(r"\b(by|without|on|ignoring)\s*\([^)]*\)", " ", bare)
    bare = re.sub(r"label_values\(\s*([a-zA-Z_:][\w:]*)\s*,[^)]*\)", r"\1", bare)
    names = re.findall(r"[a-zA-Z_:][\w:]*(?!\w*\s*\()", bare)
    return {n for n in names if n not in PROMQL_WORDS and not re.fullmatch(r"\d+\w*", n)}


def target(title: str, ref: str = "A") -> str:
    (t,) = [t for t in BY_TITLE[title]["targets"] if t["refId"] == ref]
    return t["expr"]


def mapping(defaults: dict) -> dict[str, str]:
    return {k: v["text"] for m in defaults.get("mappings", []) for k, v in m["options"].items()}


def override(panel: dict, name: str) -> dict:
    (o,) = [o for o in panel["fieldConfig"]["overrides"] if o["matcher"]["options"] == name]
    return {p["id"]: p["value"] for p in o["properties"]}


# --- structure ---------------------------------------------------------------------

def test_board_parses_with_unique_ids_and_no_overlap() -> None:
    ids = [p["id"] for p in DOC["panels"]]
    assert len(ids) == len(set(ids)) == 30
    cells: dict[tuple[int, int], int] = {}
    for p in DOC["panels"]:
        g = p["gridPos"]
        assert g["x"] + g["w"] <= 24, p["title"]
        for y in range(g["y"], g["y"] + g["h"]):
            for x in range(g["x"], g["x"] + g["w"]):
                assert (y, x) not in cells, f'{p["title"]} overlaps panel {cells[(y, x)]}'
                cells[(y, x)] = p["id"]


def test_the_install_now_band_is_on_top() -> None:
    """y=0 is the band's row; its first line (y=1) is the five stats, then the two tables;
    the Overview row closes it, and every pre-existing panel sits below."""
    top = sorted(DOC["panels"], key=pos)
    assert [p["id"] for p in top if p["gridPos"]["y"] == 0] == [BAND_ROW]
    assert PANELS[BAND_ROW]["type"] == "row" and PANELS[BAND_ROW]["title"].startswith("Install now")
    assert tuple(p["title"] for p in top if p["gridPos"]["y"] == 1) == STATS
    assert tuple(p["title"] for p in top if p["gridPos"]["y"] == 5) == TABLES
    overview = PANELS[OVERVIEW_ROW]
    assert overview["type"] == "row"
    band = [p for p in top if pos(p) < pos(overview)]
    assert {p["title"] for p in band} == {PANELS[BAND_ROW]["title"], *STATS, *TABLES}
    assert all(pos(PANELS[i]) > pos(overview) for i in KEPT)


def test_every_pre_existing_panel_is_kept_in_its_order() -> None:
    for pid, title in KEPT.items():
        assert PANELS[pid]["title"] == title
    old = [p["id"] for p in sorted(DOC["panels"], key=pos) if p["id"] in KEPT]
    assert old == list(KEPT)  # KEPT is written in the old (y, x) order
    assert "(~/.patched/config)" in PANELS[21]["description"]  # the config path's words stay
    assert "(~/.patched/config)" in PANELS[22]["description"]


def test_every_expr_names_a_series_the_exporter_writes() -> None:
    seen = set()
    for e in exprs():
        names = metrics(e)
        assert names, e
        assert names <= set(export.HELP) | OTHERS, (e, names - set(export.HELP) - OTHERS)
        seen |= names
    assert {"patched_install", "patched_install_items", "patched_detail_series"} <= seen


def test_metrics_reads_names_not_labels_or_functions() -> None:
    assert metrics('sum by (product, version) (patched_install{fix="release",in_use="true"})') == {"patched_install"}
    assert metrics("count(patched_scan_ok == 0) or vector(0)") == {"patched_scan_ok"}
    assert metrics('time() - max(node_textfile_mtime_seconds{file=~".*patched\\\\.prom"})') == {
        "node_textfile_mtime_seconds"}
    assert metrics("label_values(patched_advisory_exposed, product)") == {"patched_advisory_exposed"}


def test_to_install_says_nothing_only_on_a_zero_and_unknown_when_missing() -> None:
    """R4. 0 maps to "Nothing to install"; no sample is unknown, never nothing to do."""
    d = BY_TITLE["To install"]["fieldConfig"]["defaults"]
    assert mapping(d) == {"0": "Nothing to install"}
    assert d["noValue"].startswith("Unknown") and "Nothing" not in d["noValue"]
    kev = override(BY_TITLE["To install"], "B")
    assert kev["displayName"] == "Known exploited" and kev["mappings"] == []  # its 0 is never "nothing"
    assert [s["color"] for s in kev["thresholds"]["steps"]] == ["green", "red"]
    for title in STATS[2:]:
        assert BY_TITLE[title]["fieldConfig"]["defaults"]["noValue"] == "Unknown"


def test_names_off_says_how_to_turn_names_on() -> None:
    d = BY_TITLE["Names"]["fieldConfig"]["defaults"]
    off = mapping(d)["0"]
    assert mapping(d)["1"] == "Names on"
    assert d["noValue"] == off  # an older exporter writes no patched_detail_series
    for words in ("Names off", "~/.patched/scans", "PATCHED_DETAIL_SERIES=1", "patched scan --detail",
                  "patched schedule on"):
        assert words in off
    for title in TABLES:  # an empty table is not "nothing to do": its description says so
        assert "names off" in BY_TITLE[title]["description"].lower()
        # ...and so does the table itself: Grafana shows defaults.noValue as an empty panel's message,
        # so a "0" there would read "nothing exposed" with names off (the default)
        empty = BY_TITLE[title]["fieldConfig"]["defaults"]["noValue"]
        assert empty.startswith("Empty") and "names off" in empty and "Read To install and Names" in empty
    assert "OR names off" in BY_TITLE["Install now"]["description"]
    for column in ("install a release", "fixed upstream, no release", "brew patched", "no fix known"):
        assert override(BY_TITLE["Exposed, by product (counts)"], column)["noValue"] == "0"  # a null cell is 0


def test_four_fix_kinds_read_apart() -> None:
    """R3. Distinct text and colour; brew is keyed on fix (patched_by_brew), never on patch."""
    fix = override(PANELS[17], "fix")
    (m,) = fix["mappings"]
    assert set(m["options"]) == set(export.FIXES)
    texts = {k: v["text"] for k, v in m["options"].items()}
    colours = {k: v["color"] for k, v in m["options"].items()}
    assert len(set(texts.values())) == len(set(colours.values())) == 4
    assert texts["brew"] == "Brew already patched" and texts["none"] == "No fix known"
    assert texts["commit"] == "Fixed upstream in a commit, no release yet"
    assert colours == {"release": "orange", "commit": "yellow", "brew": "green", "none": "red"}
    assert 'fix="brew"' in target("Brew already patched")
    for e in exprs():
        if "patched_install" in e or "patched_advisory_exposed" in e:
            assert "patch=" not in e, e
    assert target("Exposed, no patch") == 'sum(patched_exposed{patch="none"})'  # brew already excluded


def test_drill_down_by_product() -> None:
    """R2. A product variable filters the per-CVE table; the grouped tables link to it."""
    (var,) = DOC["templating"]["list"]
    assert var["name"] == "product" and var["includeAll"] and var["allValue"] == ".*"
    assert var["query"]["query"] == "label_values(patched_advisory_exposed, product)"
    assert target("Exposed advisories, by product") == 'patched_advisory_exposed{product=~"$product"} == 1'
    order = PANELS[17]["transformations"][0]["options"]["indexByName"]
    assert order["fix"] == order["advisory"] + 1 and "patch" in order
    for title in TABLES:
        (link,) = override(BY_TITLE[title], "product")["links"]
        assert "var-product=${__value.raw}" in link["url"]


def test_install_now_columns_and_latest() -> None:
    org = BY_TITLE["Install now"]["transformations"][0]["options"]
    order = sorted(org["indexByName"], key=org["indexByName"].get)
    assert [org["renameByName"].get(c, c) for c in order] == [
        "product", "installed", "install", "advisories", "worst severity", "KEV", "source"]
    (m,) = override(BY_TITLE["Install now"], "install")["mappings"]
    assert m["options"]["latest"]["text"].startswith("a newer release")


# --- the exprs, under promtool ---------------------------------------------------

PROMTOOL = shutil.which("promtool")
needs_promtool = pytest.mark.skipif(PROMTOOL is None, reason="promtool not on PATH")

FILESHARE = item([adv("CVE-1", "low", fixed="1.20.9"), adv("CVE-2", "high", fixed="1.20.17"),
                  adv("CVE-3", "medium", kev=True, fixed="1.20.10"),
                  adv("CVE-4", "critical", commits=["abcdef1"]), adv("CVE-5", "critical")])
OPENSSL = item([adv("CVE-9", "critical", fixed="3.6.5")], name="openssl@3", version="3.6.4",
               source="brew-formula")
OPENSSL_UNUSED = item([adv("CVE-9", "critical", fixed="3.6.5")], name="openssl@3", version="3.5.9",
                      source="brew-formula", in_use=False)  # evict, not install
LIBFOO = item([adv("CVE-2026-58050", "high", brew="true")], name="libfoo", version="1.0",
              source="brew-formula")  # brew-patched with patch="none"
MIXED = [FILESHARE, OPENSSL, OPENSSL_UNUSED, LIBFOO]


def input_series(prom: str) -> list[dict]:
    out = []
    for ln in prom.splitlines():
        if ln and not ln.startswith("#"):
            sel, value = ln.rsplit(" ", 1)
            out.append({"series": sel, "values": value})
    return out


def evaluate(tmp_path: Path, prom: str, cases: list[tuple[str, list[tuple[str, float]]]]) -> None:
    """Every (expr, [(labels, value)]) evaluated at t=0 on the rendered series; [] = no sample."""
    tests = [{"expr": e, "eval_time": "0m", "exp_samples": [{"labels": lab, "value": v} for lab, v in want]}
             for e, want in cases]
    spec = {"rule_files": [], "evaluation_interval": "1m",
            "tests": [{"interval": "1m", "input_series": input_series(prom), "promql_expr_test": tests}]}
    path = tmp_path / "board.test.yml"
    path.write_text(json.dumps(spec, indent=1))  # JSON is YAML
    r = subprocess.run([PROMTOOL, "test", "rules", str(path)], capture_output=True, text=True, timeout=60,
                       check=False)
    assert r.returncode == 0, r.stdout + r.stderr


def stat_cases(release: list, kev: list, commit: list, brew: list, none: list, names: list) -> list:
    return [(target("To install"), release), (target("To install", "B"), kev),
            (target("Fixed upstream, no release"), commit), (target("Brew already patched"), brew),
            (target("No fix known"), none), (target("Names"), names)]


def one(v: float) -> list[tuple[str, float]]:
    return [("{}", v)]


@needs_promtool
def test_names_on_gives_a_row_per_item_to_install(tmp_path: Path) -> None:
    prom = export.render(bp.scan_of(MIXED), detail=True)
    c = 'in_use="true",source="uv-tool",product="fileshare",version="1.20.16"'
    o = 'in_use="true",source="brew-formula",product="openssl@3",version="3.6.4"'
    rows = [(f'{{__name__="patched_install",{c},fix="release",fixed="1.20.17",severity="high",kev="true"}}', 3),
            (f'{{__name__="patched_install",{o},fix="release",fixed="3.6.5",severity="critical",kev="false"}}', 1)]
    counts = "Exposed, by product (counts)"
    cp, os_, lf = ('product="fileshare",version="1.20.16"', 'product="openssl@3",version="3.6.4"',
                   'product="libfoo",version="1.0"')
    evaluate(tmp_path, prom, [
        *stat_cases(one(2), one(1), one(1), one(1), one(1), [('{__name__="patched_detail_series"}', 1)]),
        (target("Install now"), rows),
        (target(counts, "A"), [(f"{{{cp}}}", 5), (f"{{{os_}}}", 1), (f"{{{lf}}}", 1)]),
        (target(counts, "B"), [(f'{{{cp},fixed="1.20.17"}}', 3), (f'{{{os_},fixed="3.6.5"}}', 1)]),
        (target(counts, "C"), [(f"{{{cp}}}", 1)]),
        (target(counts, "D"), [(f"{{{lf}}}", 1)]),  # 58050 counts brew patched, never "no fix"
        (target(counts, "E"), [(f"{{{cp}}}", 1)]),
    ])


@needs_promtool
def test_the_drill_down_filters_the_per_cve_table(tmp_path: Path) -> None:
    prom = export.render(bp.scan_of(MIXED), detail=True)
    rows = [s["series"] for s in input_series(prom) if s["series"].startswith("patched_advisory_exposed{")]
    assert len(rows) == 8
    sel = target("Exposed advisories, by product")

    def want(product: str) -> list[tuple[str, float]]:
        # an empty label is no label to Prometheus (fix_commit="" here)
        return [("{" + re.sub(r',?\w+=""', "", f'__name__="patched_advisory_exposed",{r.split("{", 1)[1]}'), 1)
                for r in rows if f'product="{product}"' in r or product == ".*"]

    evaluate(tmp_path, prom, [(sel.replace("$product", "fileshare"), want("fileshare")),
                              (sel.replace("$product", ".*"), want(".*"))])
    assert len(want("fileshare")) == 5


@needs_promtool
def test_names_off_gives_the_count_and_the_names_off_value(tmp_path: Path) -> None:
    prom = export.render(bp.scan_of(MIXED), detail=False)
    evaluate(tmp_path, prom, [
        *stat_cases(one(2), one(1), one(1), one(1), one(1), [('{__name__="patched_detail_series"}', 0)]),
        (target("Install now"), []),  # empty: the Names stat says why
        *((target("Exposed, by product (counts)", ref), []) for ref in "ABCDE"),
    ])


@needs_promtool
def test_nothing_to_install_is_a_zero(tmp_path: Path) -> None:
    prom = export.render(bp.scan_of([LIBFOO, item([], name="ripgrep", version="15.0", source="brew-formula")]),
                         detail=True)
    evaluate(tmp_path, prom, [
        *stat_cases(one(0), [], one(0), one(1), one(0), [('{__name__="patched_detail_series"}', 1)]),
        (target("Install now"), []),
    ])
    assert mapping(BY_TITLE["To install"]["fieldConfig"]["defaults"])["0"] == "Nothing to install"


@needs_promtool
@pytest.mark.parametrize("detail", [True, False])
def test_missing_series_never_read_nothing_to_install(tmp_path: Path, detail: bool) -> None:
    """OSV failed: no count claims 0, so To install has no sample and reads Unknown."""
    prom = export.render(bp.scan_of(MIXED, osv=False), detail=detail)
    evaluate(tmp_path, prom, [
        *stat_cases([], [], [], [], [], [('{__name__="patched_detail_series"}', int(detail))]),
        (target("Install now"), []),
    ])


@needs_promtool
def test_no_scan_at_all_gives_no_sample_anywhere(tmp_path: Path) -> None:
    evaluate(tmp_path, "", [*stat_cases([], [], [], [], [], []), (target("Install now"), [])])
