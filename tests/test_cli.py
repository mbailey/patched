from pathlib import Path

import pytest
from click.testing import CliRunner

from patched import allow as allowlist
from patched import cli
from patched.cli import main


def test_help() -> None:
    result = CliRunner().invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.output
    assert "inventory" in result.output


# --- patched allow ---

def layout(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        f = root / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
    return root


@pytest.fixture
def config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = layout(tmp_path / "config", {
        "fleet/Brewfile": 'brew "a"  # the one we want\nuv "p", source: "git+ssh://git.example/~/git/repos/p.git"\n',
        "host/host1/class": "laptop\n", "class/laptop/Brewfile": 'cask "ok"\n', "host/host1/apps": "Zoom\n"})
    monkeypatch.setenv("PATCHED_CONFIG", str(root))
    monkeypatch.setattr(cli.scanner, "host", lambda: "host1")
    return root


def test_allow_shows_each_line_with_its_file(config: Path) -> None:
    r = CliRunner().invoke(main, ["allow"])
    assert r.exit_code == 0, r.output
    assert "class laptop" in r.output
    assert 'fleet/Brewfile:1' in r.output and 'brew "a"  # the one we want' in r.output
    assert 'uv "p", source: "git+ssh://git.example/~/git/repos/p.git"' in r.output
    assert 'class/laptop/Brewfile:1' in r.output and 'host/host1/apps:1' in r.output and 'app "Zoom"' in r.output
    assert "4 lines (fleet 2, class/laptop 1, host/host1 1); 0 unreadable" in r.output


def test_allow_exits_1_on_an_unreadable_line(config: Path) -> None:
    (config / "fleet/Brewfile").write_text('brew "a"\nbrew "b" if OS.mac?\n')
    r = CliRunner().invoke(main, ["allow"])
    assert r.exit_code == 1 and "unreadable:" in r.output and "Brewfile:2" in r.output


def test_a_bad_host_or_a_dangling_link_is_one_line(config: Path, tmp_path: Path,
                                                    monkeypatch: pytest.MonkeyPatch) -> None:
    """No traceback: one line and exit 2."""
    r = CliRunner().invoke(main, ["allow", "--host", "../etc"])
    assert r.exit_code == 2 and "not one path segment" in r.output and "Traceback" not in r.output
    link = tmp_path / "link"
    link.symlink_to(tmp_path / "gone")
    monkeypatch.setenv("PATCHED_CONFIG", str(link))
    for args in (["allow"], ["allow", "diff", str(config / "fleet/Brewfile")]):
        r = CliRunner().invoke(main, args)
        assert r.exit_code == 2 and "which is missing" in r.output, args


def formula(name: str, on_request: bool, deps: tuple = ()) -> dict:
    return {"source": "brew-formula", "name": name, "full_name": name, "version": "1.0",
            "on_request": on_request, "deps": list(deps)}


def _scan(items: list[dict], **stages: bool) -> dict:
    ok = {"brew": True, "apps": True, "uv": True, "npm": True, "products": True, **stages}
    return {"items": items, "stages": ok, "errors": {},
            "allow": {"products": allowlist.match(items, allowlist.products("host1"))}}


def test_check_lists_what_is_not_allowed_with_riders_nested(config: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    items = [formula("a", True), formula("c", True, ("d",)), formula("d", False, ("e",)), formula("e", False),
             formula("m", False), {"source": "brew-cask", "name": "k", "full_name": "k", "formula_deps": ["m"]},
             {"source": "npm-global", "name": "@x/y", "version": "2"}]
    monkeypatch.setattr(cli.scanner, "run", lambda **kw: _scan(items))
    r = CliRunner().invoke(main, ["allow", "check", "-q"])
    assert r.exit_code == 1
    assert "brew-formula: 1 not allowed\n  c 1.0\n    + d (rides)\n      + e (rides)\n" in r.output
    assert "brew-cask: 1 not allowed\n  k\n    + m (rides)\n" in r.output
    assert "npm-global: 1 not allowed\n  @x/y 2\n" in r.output
    assert "3 not allowed (brew-formula 1, brew-cask 1, npm-global 1), 3 riding with them" in r.output


def test_check_exits_0_when_all_is_allowed(config: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli.scanner, "run", lambda **kw: _scan([formula("a", True)]))
    r = CliRunner().invoke(main, ["allow", "check", "-q"])
    assert r.exit_code == 0 and "0 not allowed, 0 riding" in r.output


def test_check_says_a_failed_stage_and_refuses_another_host(config: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli.scanner, "run", lambda **kw: _scan([formula("a", True)], npm=False))
    r = CliRunner().invoke(main, ["allow", "check", "-q"])
    assert r.exit_code == 1 and "FAILED stages: npm" in r.output
    broken = dict(_scan([]), errors={"products": "ValueError: bad class"})
    broken["allow"]["products"] = None
    monkeypatch.setattr(cli.scanner, "run", lambda **kw: broken)
    r = CliRunner().invoke(main, ["allow", "check", "-q"])
    assert r.exit_code == 2 and "bad class" in r.output
    assert CliRunner().invoke(main, ["allow", "--host", "host2", "check"]).exit_code == 2  # a usage error


def test_diff_an_install_list(config: Path, tmp_path: Path) -> None:
    f = tmp_path / "Brewfile"
    f.write_text('tap "hashicorp/tap"\nbrew "a"\nbrew "evil/tap/a"\n'
                 'uv "p", source: "git.example:git/repos/p.git"\nuv "q"\nmas "Zoom", id: 1\nbrew "x" if y\n')
    r = CliRunner().invoke(main, ["allow", "diff", str(f)])
    assert r.exit_code == 1
    lines = r.output.splitlines()
    assert '+ brew "evil/tap/a"  (3)' in lines and '+ uv "q"  (5)' in lines
    assert '? tap "hashicorp/tap"  (1)' in lines
    assert '- cask "ok"  (class/laptop/Brewfile:1)' in lines
    assert not any(ln.startswith(("+ brew \"a\"", "+ uv \"p\"", "+ mas", "- app")) for ln in lines)
    assert "6 lines: 2 not allowed, 1 not checked, 1 unreadable; the list has 1 lines it lacks" in r.output


# --- patched scan prints the report; -q does not ---

def _full_scan() -> dict:
    jq = {"source": "brew-formula", "name": "jq", "version": "1.7", "in_use": True, "status": "exposed",
          "advisories": [{"advisory": "GHSA-x", "severity": "critical", "kev": False, "fixed": "1.8.1",
                          "fix_commits": [], "patched_by_brew": "false"}]}
    return {"host": "host1", "stamp": "20261120T142300", "started": 100.0, "finished": 101.5,
            "items": [jq], "errors": {}, "listeners": [], "launchd": [], "protections": {}, "macos": {},
            "stages": {"brew": True, "apps": True, "uv": True, "npm": True, "osv": True, "brew_patches": True,
                       "listeners": True, "launchd": True}}


@pytest.fixture
def scanned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    from patched import export, net
    textfile = tmp_path / "textfile"
    textfile.mkdir()
    monkeypatch.setattr(net, "HOME", tmp_path / "home")
    monkeypatch.setenv("PATCHED_TEXTFILE_DIR", str(textfile))
    monkeypatch.setattr(export, "TEXTFILE_DIR", textfile)
    monkeypatch.setattr(cli.scanner, "run", lambda **kw: _full_scan())
    return tmp_path


def test_scan_prints_the_report_then_the_summary_and_wrote(scanned: Path) -> None:
    r = CliRunner().invoke(main, ["scan", "--no-update"])
    assert r.exit_code == 0, r.output
    out = r.stdout
    assert out.startswith("patched  host1  scanned ")
    assert "Install now" in out and "  brew upgrade jq\n" in out and "Checked 1 of 1 item." in out
    assert out.index("Checked 1 of 1 item.") < out.index("1 items: 1 exposed") < out.index("wrote ")


def test_scan_quiet_prints_no_report(scanned: Path) -> None:
    r = CliRunner().invoke(main, ["scan", "--no-update", "-q"])
    assert r.exit_code == 0, r.output
    lines = r.stdout.splitlines()
    assert len(lines) == 2 and lines[0].startswith("1 items: 1 exposed") and lines[1].startswith("wrote ")
    assert "no report" in CliRunner().invoke(main, ["scan", "--help"]).output


def test_scan_help_shows_the_textfile_default_bare() -> None:
    from patched import export
    r = CliRunner().invoke(main, ["scan", "--help"], terminal_width=400, max_content_width=400)
    assert r.exit_code == 0
    assert f"[default: {export.TEXTFILE_DIR}]" in r.output
    assert "[default: (" not in r.output
