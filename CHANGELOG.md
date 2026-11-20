# Changelog

All notable changes to patched are documented here. The format is
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). The one
version lives in `pyproject.toml`; `scripts/release.py` bumps it with
`uv version`, mirrors it into `.claude-plugin/*.json` when present, and
stamps this file.

## [Unreleased]

### Added

- patched, born 2026-10-28.
- `patched schedule on|off|status`: an hourly `patched scan` as a user
  LaunchAgent (`com.failmode.patched-scan`, no sudo), with your PATH so no
  source reads empty; log in `~/Library/Logs/patched/scan.log`. Nothing is
  enabled until someone runs `patched schedule on`.
- `patched completions [bash|zsh|fish]`: TAB completion for every verb and
  option (click's own); `--install` writes the bash script to
  `~/.local/share/bash-completion/completions/patched`, which
  bash-completion 2 loads on the next TAB.
- Add scripts/bootstrap.sh: Homebrew setup of node_exporter, Prometheus and Grafana for patched.
- The exporter rolls advisories up per item, for the board's call
  to action. `patched_advisory_exposed` (detail) gains a `fix` label:
  `release`, `commit`, `brew` or `none`, brew first (an advisory brew
  patched reads `brew` even with `patch="none"`). New detail series
  `patched_install{source,product,version,in_use,fix,fixed,severity,kev}`:
  per item and fix kind, the advisory count, the worst severity, KEV, and
  for `release` the highest fixed version (by version order, not string;
  `latest` if any is only `available`). New counts-only
  `patched_install_items{fix,kev,in_use}`: the full zero grid, written
  only when the `osv` stage worked, its `fix="brew"` rows only when
  `brew_patches` did. New `patched_detail_series` (1 or 0): names on or
  off. Every other series is unchanged.
- The board opens with "Install now: is there something we need to
  be installing?". Stats: To install (items in use a release fixes; 0 reads
  "Nothing to install", no data reads Unknown, never nothing to do; known
  exploited in red), Names (names off says where the list is and how to
  turn names on), Fixed upstream no release, Brew already patched, No fix
  known. Tables: Install now (per item, the version that clears them all)
  and Exposed, by product (counts by fix kind). A Product variable filters
  the per-advisory table, which now shows `fix` beside the advisory. Every
  existing panel is kept, moved down under an Overview row.
- `patched report` prints what to do from the newest scan, grouped by the fix (Install now, with the commands; Wait for a release; No fix known; Already patched by Homebrew) and closed by coverage. `patched scan` prints it too; `-q` keeps it out of the hourly log.
- Each scan removes scan records older than 30 days (`PATCHED_KEEP_DAYS`; `0` keeps them all), keeping each host's newest, and says `pruned N records older than 30 days`.

### Changed

- scripts/bootstrap.sh will not replace a Prometheus or Grafana setup it did
  not write (a `prometheus.yml` without its marker line, a `prometheus.args`
  that is not its own, a `grafana.ini` whose provisioning points elsewhere):
  it stops before installing or writing anything, exit 3, in a dry run too.
  `--force` replaces them and names each one first.
- Removed `make publish`: install from a checkout. The `patched` name on PyPI is another project.
- A README for someone new to patched, and docs/ with a page per feature: what it checks, scan and report, allow lists, metrics and board, the hourly schedule, what leaves your Mac, shell completions.

### Fixed

- An advisory brew already patched no longer shows as exposed
  with no fix. A new `brew_patches` stage reads the keg's formula patches:
  `patched_advisory_exposed` carries `patched_by_brew` (`true`, `false`,
  `unknown`, `n/a`) and `fix_commit`; a `true` advisory leaves
  `patched_exposed` and the listener count and is counted in the new
  `patched_brew_patched{severity,kev,in_use}`; an item all of whose
  advisories are brew-patched is `patched`. A fix that is an upstream
  commit with no release reads `patch="commit"`, never `none`.
- `patched scan` runs on a Mac with no node_exporter: it saves the scan record and skips patched.prom. A textfile directory you name that is missing is still an error (exit 2).
- The report says where a listener is reachable in plain words (`*:8080`, `8080 on one address`, `443 via tailscale serve (tailnet)`, `443 via tailscale funnel (internet)`) instead of the internal bind kind.
- patched finds Homebrew on an Intel Mac (`/usr/local`, or `$HOMEBREW_PREFIX`), for its sources, the textfile default and the agent's PATH; off macOS, `patched scan` and `patched schedule on` say "patched scans macOS only for now" and exit 2.
- bootstrap.sh prints no prefix note for /opt/homebrew or /usr/local, and for another prefix says patched finds it when HOMEBREW_PREFIX is set; `scan --help` shows the textfile default without parentheses again.
- `patched schedule on` carries PATCHED_KEEP_DAYS into the hourly agent, so 0 keeps every record there too.
- AGPL-3.0 licence; a GitHub workflow runs make check on push and pull requests; install is one line, `uv tool install git+https://github.com/mbailey/patched`.
- Removed `patched box` and the drift alert and panel, which nothing fed; the User-Agent names the repo; tests and examples use neutral names.
