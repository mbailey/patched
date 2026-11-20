"""Progress: a line per stage on stderr, so a long scan never sits silent."""
import io

import pytest

from patched import allow, collect, kev, osv
from patched import scan as scanner
from patched.cli import StageLines


class Log:
    def __init__(self) -> None:
        self.events: list[tuple] = []

    def start(self, name: str) -> None:
        self.events.append(("start", name))

    def done(self, name: str, ok: bool, seconds: float) -> None:
        self.events.append(("done", name, ok))


MATCHED = {"loaded": True, "errors": [], "unallowed": {}, "riding": []}


@pytest.fixture
def stubbed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every stage instant and offline; npm raises, so a failure still reports done."""
    def boom() -> list:
        raise RuntimeError("npm broke")
    stubs = {
        (collect, "brew_update"): lambda: None, (collect, "brew"): lambda: ([], set()),
        (collect, "apps"): lambda casks: [], (collect, "uv_tools"): list,
        (collect, "npm_globals"): boom, (collect, "listeners"): list,
        (collect, "launchd"): list, (collect, "protections"): dict,
        (collect, "macos"): dict, (kev, "load"): lambda: (set(), None),
        (osv, "match"): lambda items, cves: None, (collect, "served_ports"): dict,
        (collect, "link"): lambda listeners, items, served: None, (allow, "services"): lambda host: (None, []),
        (allow, "products"): lambda host: {"host": host}, (allow, "match"): lambda items, plist: dict(MATCHED),
    }
    for (mod, name), fn in stubs.items():
        monkeypatch.setattr(mod, name, fn)


def test_plan_counts() -> None:
    assert len(scanner.plan()) == 16
    assert len(scanner.plan(update=False)) == 15
    assert len(scanner.plan(network=False)) == 12
    assert scanner.plan()[-2:] == ["allow", "products"]
    assert scanner.plan()[10:12] == ["osv", "brew_patches"]  # right after osv: it reads osv's advisories


def test_products_ride_in_the_scan_record(stubbed: None) -> None:
    scan = scanner.run(network=False)
    assert scan["stages"]["products"] is True and scan["allow"]["products"] == MATCHED


def test_a_failed_products_stage_leaves_none(stubbed: None, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(host: str) -> dict:
        raise ValueError("host/host1/class: class 'a b' is not one path segment")
    monkeypatch.setattr(allow, "products", boom)
    scan = scanner.run(network=False)
    assert scan["stages"]["products"] is False and scan["allow"]["products"] is None
    assert "not one path segment" in scan["errors"]["products"]


@pytest.mark.parametrize("network,update", [(True, True), (True, False), (False, True)])
def test_run_reports_exactly_the_plan(stubbed: None, network: bool, update: bool) -> None:
    log = Log()
    s = scanner.run(network=network, update=update, progress=log)
    starts = [e[1] for e in log.events if e[0] == "start"]
    dones = [e[1] for e in log.events if e[0] == "done"]
    assert starts == dones == scanner.plan(network=network, update=update)
    assert ("done", "npm", False) in log.events
    assert s["stages"]["npm"] is False


def test_stage_lines_in_a_pipe() -> None:
    out = io.StringIO()
    lines = StageLines(scanner.plan(), stream=out)
    lines.start("apps")
    lines.done("apps", True, 0.42)
    lines.start("osv")
    lines.done("osv", False, 3.0)
    assert out.getvalue() == "[ 3/16] apps 0.4 s\n[11/16] osv 3.0 s FAILED\n"


def test_stage_lines_on_a_terminal() -> None:
    class Tty(io.StringIO):
        def isatty(self) -> bool:
            return True
    out = Tty()
    lines = StageLines(scanner.plan(update=False), stream=out)
    lines.start("brew")
    assert out.getvalue() == "[ 1/15] brew ..."
    lines.done("brew", True, 1.25)
    assert out.getvalue() == "[ 1/15] brew ... 1.2 s\n"
