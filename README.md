# patched

`brew vulns` lists what is vulnerable; patched says what to do about it,
across Homebrew formulae and casks, apps, uv tools and npm globals, and
it checks that the Mac's own protections are on.

It runs on your Mac as you, reads only, needs no sudo, and takes about
half a minute. It is an alpha, built for macOS first.

## What a scan prints

```text
patched  my-mac  scanned today 15:12 (just now)

Nothing to install now.

Wait for a release  -  fixed upstream, not released yet      7 items
  libxml2      2.13.8              9 advisories  4 high
  openssl@3    3.5.9               6 advisories  4 high
  libtiff      4.7.0               1 advisory    1 high
  ...

No fix known  -  keep it only if you need it                 5 items
  gitleaks     8.30.1              1 advisory
  libssh2      1.11.1_7            1 advisory
  ...

Already patched by Homebrew  -  nothing to do                2 items
  openjpeg     2.5.4_1             2 advisories  1 high
  libssh2      1.11.1_7           14 advisories

Checked 94 of 392 items. No advisory source for the other 298: 185 have no key
(casks and apps are listed, never matched), 109 are unknown to OSV, 4 could
not be matched by version.
```

Each item lands in the group that says what to do: **Install now** (a
release fixes it, and the group ends with the upgrade commands), **Wait
for a release**, **No fix known**, or **Already patched by Homebrew**
(brew backported the fix, so the version number alone would mislead
you). An item can sit in two groups when its advisories differ, as
libssh2 does above. A row is flagged `KNOWN EXPLOITED` when CISA lists
the advisory, and `listening on ...` when the program takes connections
from beyond this Mac. The last lines say how much it could check, so
"Nothing to install now" never reads as all clear.

## Install

You need a Mac with [Homebrew](https://brew.sh) and
[uv](https://docs.astral.sh/uv/) (`brew install uv`).

```sh
uv tool install git+https://github.com/mbailey/patched
```

Do not run `uv tool install patched`: that name on PyPI belongs to an
unrelated project.

## First scan

```sh
patched scan
```

It runs `brew update` first (that refreshes brew's index and installs
nothing); `--no-update` skips it. The scan saves a record in
`~/.patched/scans/`, readable only by you. To see the report again
without scanning:

```sh
patched report
```

patched never upgrades anything itself: it prints the commands, and you
run them.

## Going further

Each feature has its own page in [docs/](docs/README.md):

- [What it checks](docs/what-it-checks.md): the sources it inventories,
  and the statuses an item can have.
- [Scan and report](docs/scan-and-report.md): the groups, the coverage
  line, the scan record and how long it is kept.
- [Allow lists](docs/allow-lists.md): say what may be installed and
  what may listen, and hear about the rest.
- [Metrics and board](docs/metrics-and-board.md): Prometheus metrics,
  alert rules and a Grafana board, set up by one script.
- [Hourly schedule](docs/hourly-schedule.md): a scan every hour, as a
  user LaunchAgent.
- [What leaves your Mac](docs/what-leaves-mac.md): every network call,
  and what it sends.
- [Shell completions](docs/shell-completions.md): TAB for every command
  and option.

## Development

`make check` runs ruff and the tests. The tests use no network.

## Licence

GNU Affero General Public License v3.0 or later: see [LICENSE](LICENSE).
