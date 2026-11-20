"""`patched completions`: the script click writes, and --install's place."""
from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from patched.cli import main


def complete(monkeypatch, words: str, cword: int) -> list[str]:
    """What bash_complete answers for the line WORDS, the cursor at word CWORD."""
    monkeypatch.setenv("COMP_WORDS", words)
    monkeypatch.setenv("COMP_CWORD", str(cword))
    r = CliRunner().invoke(main, [], prog_name="patched", env={"_PATCHED_COMPLETE": "bash_complete"},
                           standalone_mode=True)
    return [line.split(",", 1)[1] for line in r.output.splitlines() if line.startswith("plain,")]


def test_prints_the_bash_script_by_default():
    r = CliRunner().invoke(main, ["completions"])
    assert r.exit_code == 0, r.output
    assert "_patched_completion()" in r.output
    assert "_PATCHED_COMPLETE=bash_complete" in r.output


def test_zsh_and_fish_print_too():
    for shell, mark in (("zsh", "#compdef patched"), ("fish", "complete --no-files --command patched")):
        r = CliRunner().invoke(main, ["completions", shell])
        assert r.exit_code == 0, r.output
        assert mark in r.output


def test_every_verb_completes(monkeypatch):
    assert set(complete(monkeypatch, "patched ", 1)) >= {
        "allow", "completions", "inventory", "scan", "schedule"}
    assert complete(monkeypatch, "patched schedule ", 2) == ["off", "on", "status"]
    assert "--offline" in complete(monkeypatch, "patched scan --", 2)


def test_install_writes_where_bash_completion_looks(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("BASH_COMPLETION_USER_DIR", str(tmp_path))
    r = CliRunner().invoke(main, ["completions", "--install"])
    assert r.exit_code == 0, r.output
    written = tmp_path / "completions" / "patched"
    assert "_patched_completion()" in written.read_text()
    assert str(written) in r.output


def test_install_falls_back_to_xdg_data_home(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("BASH_COMPLETION_USER_DIR", raising=False)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    r = CliRunner().invoke(main, ["completions", "--install"])
    assert r.exit_code == 0, r.output
    assert (tmp_path / "bash-completion" / "completions" / "patched").is_file()


def test_install_is_bash_only(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("BASH_COMPLETION_USER_DIR", str(tmp_path))
    r = CliRunner().invoke(main, ["completions", "zsh", "--install"])
    assert r.exit_code != 0
    assert "bash only" in r.output
    assert not (tmp_path / "completions").exists()
