"""scripts/bootstrap.sh, exercised ONLY with --dry-run.

Every run here puts a fake `brew` first on a minimal PATH. The fake answers
the reads (--prefix, list, services list) from a temp prefix and refuses
anything else, logging every call, so a test can prove the script planned
changes without making one. The script is never run without --dry-run.

What only a real run does (put's backup, then the write) is tested by
lifting those functions out of the script's text into a bash of their own,
pointed at temp files: main never runs there, and nothing reaches brew.
"""
from __future__ import annotations

import functools
import hashlib
import http.server
import os
import re
import shutil
import subprocess
import sys
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bootstrap.sh"
BOARD = ROOT / "grafana" / "patched.json"
RULES = ROOT / "prometheus" / "patched.rules.yml"
FORMULAE = ("node_exporter", "prometheus", "grafana")
STEPS = [f"==> {n}/7 " for n in range(8)]

pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="bootstrap.sh is for macOS")

FAKE_BREW = r"""#!/bin/bash
echo "$*" >> "$FAKE_BREW_LOG"
case "$1" in
  --prefix) echo "$FAKE_PREFIX" ;;
  list) [ -d "$FAKE_PREFIX/Cellar/${!#}" ] ;;
  services)
    if [ "$2" = list ]; then cat "$FAKE_SERVICES" 2>/dev/null; exit 0; fi
    echo "fake brew: refused: $*" >&2; exit 99 ;;
  *) echo "fake brew: refused: $*" >&2; exit 99 ;;
esac
"""

FAKE_PROMTOOL = r"""#!/bin/bash
echo "$*" >> "$FAKE_PROMTOOL_LOG"
exit "${FAKE_PROMTOOL_RC:-0}"
"""


class Rig:
    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.prefix = tmp / "prefix"
        self.prefix.mkdir()
        self.bin = tmp / "bin"
        self.bin.mkdir()
        self.brew_log = tmp / "brew.log"
        self.promtool_log = tmp / "promtool.log"
        self.services = tmp / "services.txt"
        self._tool("brew", FAKE_BREW)
        self.env = {
            "PATH": f"{self.bin}:/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": str(tmp / "home"),
            "TMPDIR": str(tmp),
            "LANG": "C",
            "FAKE_PREFIX": str(self.prefix),
            "FAKE_BREW_LOG": str(self.brew_log),
            "FAKE_PROMTOOL_LOG": str(self.promtool_log),
            "FAKE_SERVICES": str(self.services),
        }

    def _tool(self, name: str, body: str) -> None:
        tool = self.bin / name
        tool.write_text(body)
        tool.chmod(0o755)

    def promtool(self, rc: int = 0) -> None:
        self._tool("promtool", FAKE_PROMTOOL)
        self.env["FAKE_PROMTOOL_RC"] = str(rc)

    def dry_run(self, *args: str) -> subprocess.CompletedProcess[str]:
        # /bin/bash is the 3.2 that ships with macOS: the script must run on it.
        # A new session has no controlling terminal, so a read of /dev/tty fails.
        return subprocess.run(
            ["/bin/bash", str(SCRIPT), "--dry-run", *args],
            check=False, env=self.env, capture_output=True, text=True, timeout=60,
            stdin=subprocess.DEVNULL, start_new_session=True)

    def brew_calls(self) -> list[str]:
        return self.brew_log.read_text().splitlines() if self.brew_log.exists() else []

    def snapshot(self) -> dict[str, tuple[bool, bytes, int]]:
        snap = {}
        for p in sorted(self.prefix.rglob("*")):
            st = p.lstat()
            snap[str(p.relative_to(self.prefix))] = (p.is_dir(), b"" if p.is_dir() else p.read_bytes(), st.st_mtime_ns)
        return snap


@pytest.fixture
def rig(tmp_path: Path) -> Rig:
    return Rig(tmp_path)


def would(out: str) -> list[str]:
    return [line for line in out.splitlines() if line.startswith("would:")]


def assert_reads_only(rig: Rig) -> None:
    for call in rig.brew_calls():
        assert call == "--prefix" or call.startswith("list --formula ") or call == "services list", call


# --- the right files, as an already-bootstrapped prefix holds them ---

def seed_already_right(rig: Rig) -> None:
    p = rig.prefix
    etc = p / "etc"
    textfile = p / "var/lib/node_exporter/textfile_collector"
    prov = etc / "grafana/provisioning"
    boards = etc / "grafana/dashboards/security"
    for f in FORMULAE:
        (p / "Cellar" / f).mkdir(parents=True)
    for d in (textfile, prov / "alerting", prov / "plugins", prov / "datasources", prov / "dashboards", boards,
              etc / "prometheus-rules"):
        d.mkdir(parents=True, exist_ok=True)
    rig.services.write_text(
        "Name          Status  User  File\n"
        + "".join(f"{f}  started  someone  ~/Library/LaunchAgents/homebrew.mxcl.{f}.plist\n" for f in FORMULAE))
    (etc / "node_exporter.args").write_text(
        f"--web.listen-address=127.0.0.1:9100\n--collector.textfile.directory={textfile}\n")
    shutil.copy(RULES, etc / "prometheus-rules/patched.rules.yml")
    (etc / "prometheus.yml").write_text(f"""\
# Written by patched's scripts/bootstrap.sh. A re-run puts it back;
# the file it replaced is kept as prometheus.yml.bak-<date>.
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - {etc}/prometheus-rules/*.yml

scrape_configs:
  - job_name: prometheus
    static_configs:
      - targets: ["127.0.0.1:9090"]
  - job_name: node
    static_configs:
      - targets: ["127.0.0.1:9100"]
""")
    (etc / "prometheus.args").write_text(
        f"--config.file {etc}/prometheus.yml\n--web.listen-address=127.0.0.1:9090\n"
        f"--storage.tsdb.path {p}/var/prometheus\n")
    (etc / "grafana/grafana.ini").write_text(
        f"[paths]\n;data = /var/lib/grafana\nprovisioning = {prov}\n\n"
        "[server]\n;protocol = http\nhttp_addr = 127.0.0.1\n;http_port = 3000\n")
    (prov / "datasources/prometheus.yml").write_text("""\
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    uid: PBFA97CFB590B2093
    access: proxy
    url: http://127.0.0.1:9090
    isDefault: true
    editable: false
""")
    (prov / "dashboards/patched.yml").write_text(f"""\
apiVersion: 1
providers:
  - name: patched
    folder: Security
    type: file
    allowUiUpdates: false
    options:
      path: {boards}
""")
    shutil.copy(BOARD, boards / "patched.json")


# --- fresh machine: the whole plan, nothing touched ---

def test_fresh_prefix_prints_every_step_and_touches_nothing(rig: Rig) -> None:
    before = rig.snapshot()
    r = rig.dry_run()
    assert r.returncode == 0, r.stderr
    for header in STEPS:
        assert header in r.stdout
    assert "DRY RUN" in r.stdout
    for f in FORMULAE:
        assert f"would: brew install {f}" in r.stdout
        assert f"would: brew services restart {f}" in r.stdout
    etc = rig.prefix / "etc"
    for written in ("node_exporter.args", "prometheus.yml", "prometheus.args", "prometheus-rules/patched.rules.yml",
                    "grafana/grafana.ini", "grafana/provisioning/datasources/prometheus.yml",
                    "grafana/provisioning/dashboards/patched.yml", "grafana/dashboards/security/patched.json"):
        assert f"would: write {etc / written}" in r.stdout
    assert f"would: mkdir -p {rig.prefix}/var/lib/node_exporter/textfile_collector" in r.stdout
    assert rig.snapshot() == before
    assert_reads_only(rig)
    assert "Proceed?" not in r.stdout + r.stderr


def test_dry_run_needs_no_terminal_and_no_flags_beyond_it(rig: Rig) -> None:
    # start_new_session: no controlling tty. A dry run must not ask.
    r = rig.dry_run()
    assert r.returncode == 0, r.stderr
    assert "no terminal" not in r.stderr


def test_planned_files_bind_loopback_and_point_at_the_prefix(rig: Rig) -> None:
    # Pre-seed old content so the dry run shows the planned files as diffs.
    # An "old" prometheus.args is not the script's own: --force lets it plan.
    etc = rig.prefix / "etc"
    (etc / "grafana/provisioning/datasources").mkdir(parents=True)
    for rel in ("node_exporter.args", "prometheus.args", "grafana/provisioning/datasources/prometheus.yml"):
        (etc / rel).write_text("old\n")
    r = rig.dry_run("--force")
    assert r.returncode == 0, r.stderr
    textfile = rig.prefix / "var/lib/node_exporter/textfile_collector"
    assert "+--web.listen-address=127.0.0.1:9100" in r.stdout
    assert f"+--collector.textfile.directory={textfile}" in r.stdout
    assert "+--web.listen-address=127.0.0.1:9090" in r.stdout
    assert f"+--storage.tsdb.path {rig.prefix}/var/prometheus" in r.stdout
    assert "+    uid: PBFA97CFB590B2093" in r.stdout
    assert "+    url: http://127.0.0.1:9090" in r.stdout


def test_grafana_ini_edit_is_two_keys(rig: Rig) -> None:
    ini = rig.prefix / "etc/grafana/grafana.ini"
    ini.parent.mkdir(parents=True)
    ini.write_text("[paths]\n;provisioning = conf/provisioning\n\n[server]\n;http_addr =\nhttp_port = 3000\n")
    r = rig.dry_run()
    assert r.returncode == 0, r.stderr
    prov = rig.prefix / "etc/grafana/provisioning"
    assert f"+provisioning = {prov}" in r.stdout
    assert "-;provisioning = conf/provisioning" in r.stdout
    assert "+http_addr = 127.0.0.1" in r.stdout
    assert ini.read_text().startswith("[paths]\n;provisioning")  # untouched


def test_other_prefix_prints_the_textfile_export(rig: Rig) -> None:
    r = rig.dry_run()
    assert ("note: patched finds this prefix when your shell sets HOMEBREW_PREFIX (`brew shellenv` does).\n"
            "      If it does not, add this to your shell profile:\n"
            f"        export PATCHED_TEXTFILE_DIR={rig.prefix}/var/lib/node_exporter/textfile_collector\n"
            ) in r.stdout


def prefix_note(prefix: str) -> str:
    """bootstrap.sh's prefix_note, lifted out with its prefix list, for PREFIX: what it prints."""
    m = re.search(r"^PATCHED_FINDS_PREFIXES=.*$", SCRIPT.read_text(), re.MULTILINE)
    assert m, "no PATCHED_FINDS_PREFIXES in bootstrap.sh"
    body = "\n".join(["set -euo pipefail", m.group(0), f"PREFIX={prefix}",
                      script_functions("say", "prefix_note"), 'prefix_note "$PREFIX/var/tf"'])
    r = subprocess.run(["/bin/bash", "-c", body], check=True, env={"PATH": "/usr/bin:/bin", "LANG": "C"},
                       capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
    return r.stdout


@pytest.mark.parametrize("prefix", ["/opt/homebrew", "/usr/local"])
def test_a_prefix_patched_finds_by_itself_gets_no_note(prefix: str) -> None:
    assert prefix_note(prefix) == ""


def test_any_other_prefix_gets_the_note() -> None:
    out = prefix_note("/opt/brew")
    assert out.startswith("note: patched finds this prefix when your shell sets HOMEBREW_PREFIX")
    assert out.endswith("        export PATCHED_TEXTFILE_DIR=/opt/brew/var/tf\n")


# --- idempotency: an already-right prefix ---

def test_already_right_prefix_prints_only_ok(rig: Rig) -> None:
    seed_already_right(rig)
    before = rig.snapshot()
    r = rig.dry_run()
    assert r.returncode == 0, r.stderr
    assert would(r.stdout) == []
    assert "write " not in r.stdout
    for header in STEPS:
        assert header in r.stdout
    assert r.stdout.count("\nok    ") >= 15
    for f in FORMULAE:
        assert f"ok    {f} installed" in r.stdout
        assert f"ok    {f} started" in r.stdout
    assert rig.snapshot() == before
    assert_reads_only(rig)


def test_one_wrong_file_restarts_only_its_service(rig: Rig) -> None:
    seed_already_right(rig)
    (rig.prefix / "etc/node_exporter.args").write_text("--web.listen-address=0.0.0.0:9100\n")
    r = rig.dry_run()
    assert r.returncode == 0, r.stderr
    assert would(r.stdout) == [f"would: write {rig.prefix}/etc/node_exporter.args",
                               "would: brew services restart node_exporter"]


def test_a_stopped_service_is_started_not_restarted(rig: Rig) -> None:
    seed_already_right(rig)
    rig.services.write_text(rig.services.read_text().replace("grafana  started", "grafana  none"))
    r = rig.dry_run()
    assert would(r.stdout) == ["would: brew services start grafana"]


def test_fresh_prefix_says_nothing_is_foreign(rig: Rig) -> None:
    r = rig.dry_run()
    assert r.returncode == 0, r.stderr
    assert "ok    no file here that this script did not write" in r.stdout
    assert "REPLACES" not in r.stdout


# --- ownership: a stack this script did not write is refused, unless --force ---

FOREIGN_EXIT = 3


def seed_foreign(rig: Rig, which: str) -> Path:
    """An already-right prefix with ONE file swapped for someone else's setup."""
    seed_already_right(rig)
    etc = rig.prefix / "etc"
    if which == "prometheus.yml":
        path = etc / "prometheus.yml"
        path.write_text("global:\n  scrape_interval: 15s\nscrape_configs:\n  - job_name: someone-else\n"
                        "    static_configs:\n      - targets: [\"127.0.0.1:9999\"]\n")
    elif which == "prometheus.args":
        path = etc / "prometheus.args"
        path.write_text(path.read_text() + "--web.external-url=http://127.0.0.1:9090/x/\n")
    else:
        path = etc / "grafana/grafana.ini"
        path.write_text("[paths]\nprovisioning = /elsewhere/provisioning\n\n[server]\nhttp_addr = 127.0.0.1\n")
    return path


@pytest.mark.parametrize("which", ["prometheus.yml", "prometheus.args", "grafana.ini"])
def test_a_foreign_file_is_refused_before_anything(rig: Rig, which: str) -> None:
    path = seed_foreign(rig, which)
    before = rig.snapshot()
    r = rig.dry_run()
    assert r.returncode == FOREIGN_EXIT, r.stderr
    assert "refusing" in r.stderr
    assert f"  {path}: " in r.stderr
    assert "Nothing was changed. --force replaces them (each kept as FILE.bak-" in r.stderr
    assert "==> 1/7" not in r.stdout
    assert would(r.stdout) == []
    assert rig.snapshot() == before
    assert_reads_only(rig)


def test_each_refusal_says_why(rig: Rig) -> None:
    seed_foreign(rig, "grafana.ini")
    etc = rig.prefix / "etc"
    (etc / "prometheus.yml").write_text("global: {}\n")
    (etc / "prometheus.args").write_text("--config.file /elsewhere.yml\n")
    r = rig.dry_run()
    assert r.returncode == FOREIGN_EXIT
    prov = rig.prefix / "etc/grafana/provisioning"
    assert "prometheus.yml: it has no \"# Written by patched's scripts/bootstrap.sh\" line" in r.stderr
    assert "prometheus.args: it is not the three flags this script writes" in r.stderr
    assert f"grafana.ini: its [paths] provisioning is /elsewhere/provisioning, not {prov}" in r.stderr


def test_a_fresh_prefix_with_a_brew_stock_grafana_ini_is_not_foreign(rig: Rig) -> None:
    # Brew's stock ini comments the key out; a commented key is not a setting.
    ini = rig.prefix / "etc/grafana/grafana.ini"
    ini.parent.mkdir(parents=True)
    ini.write_text("[paths]\n;provisioning = conf/provisioning\n#provisioning = /elsewhere\n\n"
                   "[other]\nprovisioning = /not/paths\n")
    r = rig.dry_run()
    assert r.returncode == 0, r.stderr


def test_a_brew_stock_prometheus_args_is_not_foreign(rig: Rig) -> None:
    # Brew's stock args are exactly the script's three flags: nothing is lost.
    etc = rig.prefix / "etc"
    etc.mkdir()
    (etc / "prometheus.args").write_text(
        f"--config.file {etc}/prometheus.yml\n--web.listen-address=127.0.0.1:9090\n"
        f"--storage.tsdb.path {rig.prefix}/var/prometheus\n")
    r = rig.dry_run()
    assert r.returncode == 0, r.stderr
    assert f"ok    {etc}/prometheus.args" in r.stdout


# Brew's stock prometheus.yml, byte for byte: what `brew install prometheus`
# leaves before step 4 writes the script's own. Source: homebrew-core
# Formula/p/prometheus.rb, its (buildpath/"prometheus.yml").write <<~YAML
# heredoc (the 129-byte file a fresh install leaves).
STOCK_YML = """\
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: "prometheus"
    static_configs:
    - targets: ["localhost:9090"]
"""


def test_stock_yml_is_brews_129_bytes() -> None:
    assert len(STOCK_YML.encode()) == 129


def test_the_script_carries_brews_stock_yml_byte_for_byte() -> None:
    r = subprocess.run(["/bin/bash", "-c", script_functions("brew_stock_yml") + "\nbrew_stock_yml"],
                       check=True, capture_output=True, timeout=60, stdin=subprocess.DEVNULL)
    assert r.stdout == STOCK_YML.encode()


def test_a_brew_stock_prometheus_yml_is_not_foreign(rig: Rig) -> None:
    # A first run that died after `brew install prometheus`: re-running must
    # not need --force, and the stock file is replaced like any old one.
    seed_already_right(rig)
    yml = rig.prefix / "etc/prometheus.yml"
    yml.write_text(STOCK_YML)
    r = rig.dry_run()
    assert r.returncode == 0, r.stderr
    assert "ok    no file here that this script did not write" in r.stdout
    assert would(r.stdout) == [f"would: write {yml}", "would: brew services restart prometheus"]


@pytest.mark.parametrize("change", [
    ("15s", "16s"),                           # one byte changed
    ("localhost:9090", "localhost:9091"),     # one byte changed, in the target
    ('["localhost:9090"]\n', '["localhost:9090"]'),  # the last newline dropped
    ('["localhost:9090"]\n', '["localhost:9090"]\n\n'),  # one byte added
])
def test_a_stock_prometheus_yml_one_byte_off_is_refused(rig: Rig, change: tuple[str, str]) -> None:
    seed_already_right(rig)
    yml = rig.prefix / "etc/prometheus.yml"
    text = STOCK_YML.replace(*change)
    assert text != STOCK_YML
    yml.write_text(text)
    r = rig.dry_run()
    assert r.returncode == FOREIGN_EXIT, r.stderr
    assert f"  {yml}: it has no " in r.stderr


def test_an_older_file_of_its_own_is_replaced_without_force(rig: Rig) -> None:
    # The marker, not the content, says whose prometheus.yml it is.
    seed_already_right(rig)
    yml = rig.prefix / "etc/prometheus.yml"
    yml.write_text(yml.read_text().replace("scrape_interval: 15s", "scrape_interval: 30s"))
    r = rig.dry_run()
    assert r.returncode == 0, r.stderr
    assert would(r.stdout) == [f"would: write {yml}", "would: brew services restart prometheus"]


@pytest.mark.parametrize("which", ["prometheus.yml", "prometheus.args", "grafana.ini"])
def test_force_proceeds_and_names_what_it_replaces(rig: Rig, which: str) -> None:
    path = seed_foreign(rig, which)
    before = rig.snapshot()
    r = rig.dry_run("--force")
    assert r.returncode == 0, r.stderr
    head = r.stdout.split("==> 1/7")[0]
    assert "--force: these files were not written by this script, and a real run REPLACES them" in head
    assert f"\n  {path}: " in head
    assert f"would: write {path}" in r.stdout
    assert rig.snapshot() == before
    assert_reads_only(rig)


def test_force_on_a_prefix_of_its_own_names_nothing(rig: Rig) -> None:
    seed_already_right(rig)
    r = rig.dry_run("--force")
    assert r.returncode == 0, r.stderr
    assert would(r.stdout) == []
    assert "REPLACES" not in r.stdout


def test_help_names_force(rig: Rig) -> None:
    r = subprocess.run(["/bin/bash", str(SCRIPT), "--dry-run", "--help"], check=False, env=rig.env, capture_output=True,
                       text=True, timeout=60, stdin=subprocess.DEVNULL)
    assert r.returncode == 0
    assert "[--force]" in r.stdout
    assert "      --force " in r.stdout
    assert rig.brew_calls() == []


# --- symlinks: nothing is written through a link, even under --force ---

CONFIGS = {"prometheus.yml": "prometheus.yml", "prometheus.args": "prometheus.args",
           "grafana.ini": "grafana/grafana.ini"}
LINK_REFUSAL = "bootstrap: refusing: this run would write through a symlink, and this script never does:"
LINK_ADVICE = ("Nothing was changed. --force does not override this: replace each link by hand with a "
               "regular file or directory, then re-run.")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def shas(root: Path) -> dict[str, str]:
    return {str(f.relative_to(root)): sha(f) for f in sorted(root.rglob("*")) if f.is_file()}


def link_config(rig: Rig, which: str, foreign: bool) -> tuple[Path, Path]:
    """An already-right prefix whose `which` is a symlink into a sibling temp dir.

    foreign=False: the target holds what the script would write anyway (its
    own marker and all): a link is refused for being a link, not for content.
    """
    if foreign:
        seed_foreign(rig, which)
    else:
        seed_already_right(rig)
    link = rig.prefix / "etc" / CONFIGS[which]
    target = rig.tmp / "elsewhere-repo" / which
    target.parent.mkdir(exist_ok=True)
    link.rename(target)
    link.symlink_to(target)
    return link, target


def link_dir(rig: Rig, rel: str) -> tuple[Path, Path]:
    """Move prefix/rel to a sibling temp dir and leave a symlink to it in its place."""
    link = rig.prefix / rel
    target = rig.tmp / "elsewhere-repo" / rel.replace("/", "-")
    target.parent.mkdir(exist_ok=True)
    link.rename(target)
    link.symlink_to(target)
    return link, target


def assert_link_refused(rig: Rig, r: subprocess.CompletedProcess[str], before: dict) -> None:
    assert r.returncode == FOREIGN_EXIT, r.stderr
    assert LINK_REFUSAL in r.stderr
    assert LINK_ADVICE in r.stderr
    assert "==> 1/7" not in r.stdout
    assert would(r.stdout) == []
    assert "REPLACES" not in r.stdout
    assert rig.snapshot() == before
    assert_reads_only(rig)


@pytest.mark.parametrize("foreign", [False, True], ids=["own-content", "foreign-content"])
@pytest.mark.parametrize("which", list(CONFIGS))
@pytest.mark.parametrize("force", [(), ("--force",)], ids=["plain", "force"])
def test_a_symlinked_config_is_refused_even_with_force(rig: Rig, which: str, foreign: bool,
                                                       force: tuple[str, ...]) -> None:
    link, target = link_config(rig, which, foreign)
    target_sha = sha(target)
    before = rig.snapshot()
    r = rig.dry_run(*force)
    assert_link_refused(rig, r, before)
    assert f"\n  {link}: it is a symlink (-> {target})\n" in r.stderr
    assert sha(target) == target_sha
    assert link.is_symlink() and link.readlink() == target


# The file is regular, but a directory above it is a link
# out of the prefix. A -L test on the file does not see it.
@pytest.mark.parametrize("foreign", [False, True], ids=["own-content", "foreign-content"])
@pytest.mark.parametrize("force", [(), ("--force",)], ids=["plain", "force"])
def test_a_linked_grafana_dir_is_refused_even_with_force(rig: Rig, foreign: bool, force: tuple[str, ...]) -> None:
    if foreign:
        seed_foreign(rig, "grafana.ini")
    else:
        seed_already_right(rig)
    link, target = link_dir(rig, "etc/grafana")
    target_shas = shas(target)
    before = rig.snapshot()
    r = rig.dry_run(*force)
    assert_link_refused(rig, r, before)
    assert f"\n  {link}/grafana.ini: under {link} -> {target}, which leads out of the prefix (" in r.stderr
    assert shas(target) == target_shas
    assert (target / "grafana.ini").is_file()


# Every other directory a step writes under, linked out of the prefix.
@pytest.mark.parametrize("rel, written", [
    ("etc", "etc/prometheus.yml"),
    ("etc/prometheus-rules", "etc/prometheus-rules/patched.rules.yml"),
    ("etc/grafana/provisioning", "etc/grafana/provisioning/datasources/prometheus.yml"),
    ("etc/grafana/provisioning/datasources", "etc/grafana/provisioning/datasources/prometheus.yml"),
    ("etc/grafana/dashboards", "etc/grafana/dashboards/security/patched.json"),
    ("etc/grafana/dashboards/security", "etc/grafana/dashboards/security/patched.json"),
    ("var/lib/node_exporter", "var/lib/node_exporter/textfile_collector"),
])
def test_any_linked_dir_out_of_the_prefix_is_refused_with_force(rig: Rig, rel: str, written: str) -> None:
    seed_already_right(rig)
    link, target = link_dir(rig, rel)
    target_shas = shas(target)
    before = rig.snapshot()
    r = rig.dry_run("--force")
    assert_link_refused(rig, r, before)
    assert f"\n  {rig.prefix / written}: under {link} -> {target}, which leads out of the prefix (" in r.stderr
    assert shas(target) == target_shas


def test_a_linked_dir_not_yet_holding_its_file_is_refused(rig: Rig) -> None:
    # Fresh but for one link: etc/grafana -> an empty sibling dir. Everything
    # below it is still to be made; mkdir -p would build it outside.
    (rig.prefix / "etc").mkdir()
    target = rig.tmp / "elsewhere-repo/grafana"
    target.mkdir(parents=True)
    (rig.prefix / "etc/grafana").symlink_to(target)
    r = rig.dry_run("--force")
    assert r.returncode == FOREIGN_EXIT, r.stderr
    assert f"  {rig.prefix}/etc/grafana/provisioning/datasources/prometheus.yml: under {rig.prefix}/etc/grafana -> " in r.stderr
    assert list(target.iterdir()) == []


def test_a_link_that_stays_inside_the_prefix_is_fine(rig: Rig) -> None:
    # A linked dir whose real path is still under the prefix writes nothing
    # outside it: only a link out of the prefix (or a linked file) is refused.
    seed_already_right(rig)
    inside = rig.prefix / "var/elsewhere-rules"
    inside.parent.mkdir(parents=True, exist_ok=True)
    (rig.prefix / "etc/prometheus-rules").rename(inside)
    (rig.prefix / "etc/prometheus-rules").symlink_to(inside)
    r = rig.dry_run()
    assert r.returncode == 0, r.stderr
    assert would(r.stdout) == []


def test_a_sibling_whose_name_starts_with_the_prefix_is_outside(rig: Rig) -> None:
    # "Under" is by path component: <prefix>2 is not under <prefix>.
    seed_already_right(rig)
    sibling = rig.tmp / (rig.prefix.name + "2")
    sibling.mkdir()
    link = rig.prefix / "etc/prometheus-rules"
    link.rename(sibling / "prometheus-rules")
    link.symlink_to(sibling / "prometheus-rules")
    r = rig.dry_run("--force")
    assert r.returncode == FOREIGN_EXIT, r.stderr
    assert f"under {link} -> {sibling}/prometheus-rules, which leads out of the prefix (" in r.stderr


def test_a_prefix_that_is_itself_a_symlink_still_passes(rig: Rig) -> None:
    # A relocated brew: the prefix is a link, its own real path is the bound.
    real = rig.tmp / "real-prefix"
    rig.prefix.rename(real)
    rig.prefix.symlink_to(real)
    r = rig.dry_run()
    assert r.returncode == 0, r.stderr
    assert f"ok    nothing it writes is, or is under, a symlink out of {real.resolve()}" in r.stdout
    assert f"would: write {rig.prefix}/etc/prometheus.yml" in r.stdout


def test_an_already_right_prefix_that_is_itself_a_symlink_prints_only_ok(rig: Rig) -> None:
    seed_already_right(rig)
    real = rig.tmp / "real-prefix"
    rig.prefix.rename(real)
    rig.prefix.symlink_to(real)
    r = rig.dry_run()
    assert r.returncode == 0, r.stderr
    assert would(r.stdout) == []


def test_every_symlinked_config_is_named(rig: Rig) -> None:
    seed_already_right(rig)
    elsewhere = rig.tmp / "elsewhere-repo"
    elsewhere.mkdir()
    pairs = []
    for which, rel in CONFIGS.items():
        link = rig.prefix / "etc" / rel
        target = elsewhere / which
        link.rename(target)
        link.symlink_to(target)
        pairs.append((link, target))
    r = rig.dry_run("--force")
    assert r.returncode == FOREIGN_EXIT, r.stderr
    for link, target in pairs:
        assert f"  {link}: it is a symlink (-> {target})" in r.stderr


def test_a_dangling_symlinked_config_is_refused(rig: Rig) -> None:
    # A link to nowhere: writing it would create the target outside the prefix.
    etc = rig.prefix / "etc"
    etc.mkdir()
    target = rig.tmp / "elsewhere-repo/prometheus.yml"
    (etc / "prometheus.yml").symlink_to(target)
    r = rig.dry_run("--force")
    assert r.returncode == FOREIGN_EXIT, r.stderr
    assert f"  {etc / 'prometheus.yml'}: it is a symlink (-> {target})" in r.stderr
    assert not target.exists()


def test_a_dangling_linked_dir_is_refused(rig: Rig) -> None:
    (rig.prefix / "etc").mkdir()
    target = rig.tmp / "elsewhere-repo/grafana"
    (rig.prefix / "etc/grafana").symlink_to(target)
    r = rig.dry_run("--force")
    assert r.returncode == FOREIGN_EXIT, r.stderr
    assert f"under {rig.prefix}/etc/grafana -> {target}, which leads out of the prefix (" in r.stderr
    assert not target.exists()


def test_no_symlink_says_so(rig: Rig) -> None:
    seed_already_right(rig)
    r = rig.dry_run()
    assert r.returncode == 0, r.stderr
    assert "ok    nothing it writes is, or is under, a symlink out of " in r.stdout


def test_any_other_symlinked_file_it_writes_is_refused_first(rig: Rig) -> None:
    # node_exporter.args is not one of the three configs: the preflight
    # names it too, before step 1.
    seed_already_right(rig)
    link = rig.prefix / "etc/node_exporter.args"
    target = rig.tmp / "elsewhere-repo/node_exporter.args"
    target.parent.mkdir()
    link.rename(target)
    target_sha = sha(target)
    link.symlink_to(target)
    before = rig.snapshot()
    r = rig.dry_run("--force")
    assert_link_refused(rig, r, before)
    assert f"  {link}: it is a symlink (-> {target})" in r.stderr
    assert sha(target) == target_sha


# --- put's backup, in isolation (a real run's write, never the script's main) ---

def script_functions(*names: str) -> str:
    """The named functions' text, lifted out of bootstrap.sh as they stand."""
    text = SCRIPT.read_text()
    out = []
    for name in names:
        m = (re.search(rf"^{name}\(\) \{{ [^\n]*\}}$", text, re.MULTILINE)
             or re.search(rf"^{name}\(\) \{{\n.*?^\}}$", text, re.MULTILINE | re.DOTALL))
        assert m, f"no function {name} in {SCRIPT}"
        out.append(m.group(0))
    return "\n".join(out)


# put's real-run path, with `date` fixed at FAKE_STAMP (YYYYMMDD-HHMMSS).
PUT_HARNESS = """set -euo pipefail
date() { printf '%s\\n' "$FAKE_STAMP"; }
DRY_RUN=${PUT_DRY_RUN:-0}
FOREIGN_EXIT=3
CHANGED=" "
WORK=$PUT_WORK
PREFIX=$PUT_PREFIX
PREAL=$(cd "$PREFIX" && pwd -P)
"""


class Put:
    def __init__(self, tmp: Path) -> None:
        self.prefix = tmp
        self.dir = tmp / "etc"
        self.dir.mkdir()
        self.work = tmp / "work"
        self.work.mkdir()
        self.file = self.dir / "prometheus.yml"
        self.body = PUT_HARNESS + script_functions("say", "ok", "mark_changed", "backup", "first_link", "leaves",
                                                     "link_trouble", "put") + \
            '\nput "$PUT_FILE" prometheus <"$PUT_NEW"\nprintf "changed:%s\\n" "$CHANGED"\n'

    def __call__(self, new: str, stamp: str = "20261029-075300", dry_run: bool = False,
                 file: Path | None = None) -> subprocess.CompletedProcess[str]:
        src = self.work / "new"
        src.write_text(new)
        env = {"PATH": "/usr/bin:/bin", "LANG": "C", "FAKE_STAMP": stamp, "PUT_WORK": str(self.work),
               "PUT_FILE": str(file or self.file), "PUT_NEW": str(src), "PUT_DRY_RUN": "1" if dry_run else "0",
               "PUT_PREFIX": str(self.prefix)}
        return subprocess.run(["/bin/bash", "-c", self.body], check=False, env=env, capture_output=True,
                              text=True, timeout=60, stdin=subprocess.DEVNULL)

    def backups(self) -> dict[str, str]:
        return {p.name: p.read_text() for p in sorted(self.dir.glob("prometheus.yml.bak-*"))}


@pytest.fixture
def put(tmp_path: Path) -> Put:
    return Put(tmp_path)


def test_put_backs_up_the_file_it_replaces(put: Put) -> None:
    put.file.write_text("stock\n")
    r = put("own\n")
    assert r.returncode == 0, r.stderr
    assert put.file.read_text() == "own\n"
    assert put.backups() == {"prometheus.yml.bak-20261029": "stock\n"}
    assert f"kept the old one as {put.file}.bak-20261029" in r.stdout
    assert "changed: prometheus " in r.stdout


def test_a_second_replacement_the_same_day_keeps_both_copies(put: Put) -> None:
    # A morning run backed up brew's stock file; later the
    # same day someone's marker-less yml is replaced by --force. Both survive.
    put.file.write_text("stock\n")
    assert put("own\n", stamp="20261029-075300").returncode == 0
    put.file.write_text("someone else's setup\n")
    r = put("own\n", stamp="20261029-190000")
    assert r.returncode == 0, r.stderr
    assert put.file.read_text() == "own\n"
    assert put.backups() == {
        "prometheus.yml.bak-20261029": "stock\n",
        "prometheus.yml.bak-20261029-190000": "someone else's setup\n",
    }
    assert f"kept the old one as {put.file}.bak-20261029-190000" in r.stdout


def test_a_third_replacement_in_the_same_second_takes_a_new_name(put: Put) -> None:
    put.file.write_text("one\n")
    for old, new in (("one\n", "a\n"), ("two\n", "a\n"), ("three\n", "a\n")):
        put.file.write_text(old)
        assert put(new, stamp="20261029-190000").returncode == 0
    assert put.backups() == {
        "prometheus.yml.bak-20261029": "one\n",
        "prometheus.yml.bak-20261029-190000": "two\n",
        "prometheus.yml.bak-20261029-190000-2": "three\n",
    }


def test_a_file_already_kept_today_is_not_copied_twice(put: Put) -> None:
    put.file.write_text("stock\n")
    assert put("own\n").returncode == 0
    put.file.write_text("stock\n")  # put back as it was this morning
    r = put("own\n", stamp="20261029-190000")
    assert r.returncode == 0, r.stderr
    assert put.backups() == {"prometheus.yml.bak-20261029": "stock\n"}
    assert f"already kept as {put.file}.bak-20261029" in r.stdout


def test_an_existing_backup_is_never_overwritten(put: Put) -> None:
    bak = put.dir / "prometheus.yml.bak-20261029"
    bak.write_text("kept by hand\n")
    put.file.write_text("current\n")
    assert put("own\n").returncode == 0
    assert bak.read_text() == "kept by hand\n"
    assert put.backups()["prometheus.yml.bak-20261029-075300"] == "current\n"


def test_put_of_equal_content_writes_and_backs_up_nothing(put: Put) -> None:
    put.file.write_text("own\n")
    r = put("own\n")
    assert r.returncode == 0, r.stderr
    assert f"ok    {put.file}" in r.stdout
    assert put.backups() == {}
    assert "changed: \n" in r.stdout


def test_put_of_a_new_file_backs_up_nothing(put: Put) -> None:
    r = put("own\n")
    assert r.returncode == 0, r.stderr
    assert put.file.read_text() == "own\n"
    assert put.backups() == {}


@pytest.mark.parametrize("dry_run", [False, True], ids=["real", "dry-run"])
@pytest.mark.parametrize("same", [False, True], ids=["new-content", "same-content"])
def test_put_never_writes_through_a_symlink(put: Put, tmp_path: Path, dry_run: bool, same: bool) -> None:
    target = tmp_path / "elsewhere-repo/prometheus.yml"
    target.parent.mkdir()
    target.write_text("someone's repo file\n")
    target_sha = sha(target)
    put.file.symlink_to(target)
    r = put("someone's repo file\n" if same else "own\n", dry_run=dry_run)
    assert r.returncode == 3, r.stdout
    assert f"refusing to write {put.file}: it is a symlink (-> {target}). This script never writes through a link." \
        in r.stderr
    assert "Replace the link by hand, then re-run. --force does not override this." in r.stderr
    assert "changed:" not in r.stdout  # it stopped inside put
    assert sha(target) == target_sha
    assert put.file.is_symlink()
    assert put.backups() == {}


def r_file(put: Put, exists: bool) -> Path:
    return put.dir / ("grafana/grafana.ini" if exists else "grafana/provisioning/datasources/prometheus.yml")


@pytest.mark.parametrize("dry_run", [False, True], ids=["real", "dry-run"])
@pytest.mark.parametrize("exists", [False, True], ids=["file-to-make", "file-there"])
def test_put_never_writes_under_a_dir_linked_out_of_the_prefix(put: Put, tmp_path: Path, dry_run: bool,
                                                                exists: bool) -> None:
    outside = tmp_path.parent / (tmp_path.name + "-outside")
    (outside / "grafana").mkdir(parents=True)
    if exists:
        (outside / "grafana/grafana.ini").write_text("someone's ini\n")
    before = shas(outside)
    (put.dir / "grafana").symlink_to(outside / "grafana")
    r = put("own\n", dry_run=dry_run, file=r_file(put, exists))
    assert r.returncode == 3, r.stdout
    assert f"refusing to write {r_file(put, exists)}: under {put.dir}/grafana -> {outside}/grafana, which leads out of " \
        f"the prefix ({put.prefix.resolve()}). This script never writes through a link." in r.stderr
    assert "changed:" not in r.stdout
    assert shas(outside) == before
    assert sorted(p.name for p in (outside / "grafana").iterdir()) == (["grafana.ini"] if exists else [])


def test_put_writes_under_a_link_that_stays_inside_the_prefix(put: Put) -> None:
    (put.prefix / "real-grafana").mkdir()
    (put.dir / "grafana").symlink_to(put.prefix / "real-grafana")
    r = put("own\n", file=put.dir / "grafana/provisioning/x.yml")
    assert r.returncode == 0, r.stderr
    assert (put.prefix / "real-grafana/provisioning/x.yml").read_text() == "own\n"


def test_put_under_a_prefix_that_is_itself_a_link(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "linked").symlink_to(real)
    put = Put(tmp_path / "linked")
    r = put("own\n")
    assert r.returncode == 0, r.stderr
    assert (real / "etc/prometheus.yml").read_text() == "own\n"


def test_the_backup_names_match_no_config_glob(put: Put) -> None:
    # rule_files loads prometheus-rules/*.yml; Grafana provisioning reads
    # *.yml/*.yaml, dashboards *.json. No backup name ends in any of them.
    put.file.write_text("one\n")
    put("a\n")
    put.file.write_text("two\n")
    put("a\n")
    for name in put.backups():
        assert not name.endswith((".yml", ".yaml", ".json")), name


def test_refusal_and_force_header_name_both_backup_forms(rig: Rig) -> None:
    seed_foreign(rig, "prometheus.yml")
    refused = rig.dry_run()
    forced = rig.dry_run("--force")
    day = refused.stderr.split("FILE.bak-")[1][:8]
    assert day.isdigit()
    names = f"each kept as FILE.bak-{day}, or FILE.bak-{day}-HHMMSS when that name already holds an earlier backup"
    assert f"Nothing was changed. --force replaces them ({names})." in refused.stderr
    assert f"({names}):" in forced.stdout.split("==> 1/7")[0]


# --- what it says at the edges ---

# `curl ... | bash` runs whichever bash is first on PATH: macOS's 3.2, or
# Homebrew's 5.x. Inside a function, 5.x names the bash binary in
# BASH_SOURCE[0] when the script came from stdin; 3.2 leaves it unset.
PIPED_BASHES = [b for b in ("/bin/bash", "/opt/homebrew/bin/bash", "/usr/local/bin/bash") if Path(b).exists()]


@pytest.mark.parametrize("bash", PIPED_BASHES)
def test_piped_without_assets_says_pass_assets(rig: Rig, tmp_path: Path, bash: str) -> None:
    # curl ... | bash: the script arrives on stdin, with no repo beside it.
    with SCRIPT.open() as script:
        r = subprocess.run([bash, "-s", "--", "--dry-run"], check=False, env=rig.env, capture_output=True,
                           text=True, timeout=60, stdin=script, cwd=tmp_path, start_new_session=True)
    assert r.returncode == 1
    assert "piped: pass --assets URL" in r.stderr
    assert "==> 1/7" not in r.stdout
    assert_reads_only(rig)


def test_next_names_a_command(rig: Rig) -> None:
    r = rig.dry_run()
    assert r.returncode == 0, r.stderr
    assert f"Next: install patched from this checkout: uv tool install {ROOT}" in r.stdout


def test_next_without_a_checkout_names_the_repo(rig: Rig, served: tuple[str, Path]) -> None:
    url, _ = served
    r = rig.dry_run("--assets", url)
    assert r.returncode == 0, r.stderr
    assert "Next: install patched: uv tool install git+https://github.com/mbailey/patched" in r.stdout


# --- promtool ---

def test_promtool_checks_rules_in_a_dry_run_but_never_config(rig: Rig) -> None:
    rig.promtool()
    r = rig.dry_run()
    assert r.returncode == 0, r.stderr
    calls = rig.promtool_log.read_text().splitlines()
    assert calls == [f"check rules {RULES}"]


def test_promtool_rejecting_the_rules_stops_before_prometheus(rig: Rig) -> None:
    rig.promtool(rc=1)
    r = rig.dry_run()
    assert r.returncode == 1
    assert "promtool rejects" in r.stderr
    assert "would: write" not in r.stdout.split("==> 4/7")[1]
    assert "==> 5/7" not in r.stdout


# --- assets ---

@pytest.fixture
def served(tmp_path: Path) -> Iterator[tuple[str, Path]]:
    root = tmp_path / "served"
    for src, rel in ((BOARD, "grafana/patched.json"), (RULES, "prometheus/patched.rules.yml")):
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(src, root / rel)
    handler = functools.partial(QuietHandler, directory=str(root))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", root
    finally:
        server.shutdown()


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args: object) -> None:
        pass


def sums(root: Path, board: str | None = None) -> None:
    def h(rel: str) -> str:
        return hashlib.sha256((root / rel).read_bytes()).hexdigest()
    (root / "SHA256SUMS").write_text(
        f"{board or h('grafana/patched.json')}  grafana/patched.json\n"
        f"{h('prometheus/patched.rules.yml')}  prometheus/patched.rules.yml\n"
        f"{'0' * 64}  bootstrap.sh\n")


def test_assets_by_url_without_sums_say_not_checked(rig: Rig, served: tuple[str, Path]) -> None:
    url, _ = served
    r = rig.dry_run("--assets", url)
    assert r.returncode == 0, r.stderr
    assert "no SHA256SUMS beside the assets: not checked" in r.stdout


def test_assets_by_url_with_good_sums(rig: Rig, served: tuple[str, Path]) -> None:
    url, root = served
    sums(root)
    r = rig.dry_run(f"--assets={url}/")
    assert r.returncode == 0, r.stderr
    assert "ok    sha256 grafana/patched.json" in r.stdout
    assert "ok    sha256 prometheus/patched.rules.yml" in r.stdout


def test_a_sums_mismatch_stops_before_anything(rig: Rig, served: tuple[str, Path]) -> None:
    url, root = served
    sums(root, board="f" * 64)
    before = rig.snapshot()
    r = rig.dry_run("--assets", url)
    assert r.returncode == 1
    assert "grafana/patched.json does not match SHA256SUMS" in r.stderr
    assert "==> 1/7" not in r.stdout
    assert rig.snapshot() == before


def test_a_missing_asset_url_stops(rig: Rig, served: tuple[str, Path]) -> None:
    url, root = served
    (root / "prometheus/patched.rules.yml").unlink()
    r = rig.dry_run("--assets", url)
    assert r.returncode == 1
    assert "not found (HTTP 404)" in r.stderr
    assert "==> 1/7" not in r.stdout


def test_a_directory_without_assets_stops(rig: Rig, tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    r = rig.dry_run("--assets", str(empty))
    assert r.returncode == 1
    assert "asset grafana/patched.json not found" in r.stderr
    assert "==> 1/7" not in r.stdout


def test_unknown_argument_is_refused(rig: Rig) -> None:
    r = rig.dry_run("--frobnicate")
    assert r.returncode == 1
    assert "unknown argument" in r.stderr
    assert rig.brew_calls() == []


# --- the assets the script ships ---

def test_board_keeps_its_uids() -> None:
    text = BOARD.read_text()
    assert text.count("PBFA97CFB590B2093") == 63  # the Install now band (19), the product variable (1)
    assert '"uid": "patched"' in text


def test_rules_keep_all_thirteen_alerts() -> None:
    text = RULES.read_text()
    assert text.startswith("#") and "\ngroups:\n  - name: patched\n" in text
    assert len(re.findall(r"^      - alert: Patched\w+$", text, re.MULTILINE)) == 13


# --- nothing personal: generic patterns only (the named check lives outside the repo) ---

SHIPPED = (SCRIPT, BOARD, RULES)
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+")


@pytest.mark.parametrize("path", SHIPPED, ids=lambda p: p.name)
def test_nothing_personal(path: Path) -> None:
    text = path.read_text()
    assert "/Users/" not in text
    assert ".ts.net" not in text
    assert EMAIL.findall(text) == []
    assert "@" not in text.replace('"$@"', "").replace("[@]", "")


def test_the_brew_prefix_literals_appear_once_as_the_named_constant() -> None:
    for literal in ("/opt/homebrew", "/usr/local"):
        lines = [line for line in SCRIPT.read_text().splitlines() if literal in line]
        assert lines == ['PATCHED_FINDS_PREFIXES="/opt/homebrew /usr/local"'], literal
        for asset in (BOARD, RULES):
            assert literal not in asset.read_text()


def test_script_is_executable() -> None:
    assert os.access(SCRIPT, os.X_OK)
