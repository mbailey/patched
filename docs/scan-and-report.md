# Scan and report

## A scan

`patched scan` runs these steps, each one on its own, so one failing
does not stop the rest:

1. `brew update`, to refresh brew's index (it installs nothing).
   `--no-update` skips it.
2. The inventory (see [What it checks](what-it-checks.md)).
3. Matching: CISA's catalog, then OSV, then Homebrew's own patches.
   `--offline` skips the network: the inventory is saved, and the
   report says that nothing was checked.
4. It saves the scan record, prints the report, and writes the metrics
   file if you use them (see [Metrics and board](metrics-and-board.md)).

Progress goes to stderr, a line a step (`[11/15] brew_patches 0.0 s`).
`-q` prints no progress and no report, only the summary line and what
was written: that is what the [hourly schedule](hourly-schedule.md)
runs. `-n` writes nothing and prints the metrics file instead.

A scan exits 1 when any step failed, and names it on the last line.

## The report

`patched report` prints the report of the newest record again, with no
new scan. Items are grouped by what to do, most urgent first:

- **Install now:** a release fixes it. The group ends with the commands
  that install them, one line per package manager: `brew upgrade`,
  `brew upgrade --cask`, `uv tool upgrade`, `npm install -g`. patched
  never runs them. When there is nothing to install, it says `Nothing
  to install now.`
- **Wait for a release:** fixed upstream in a commit, not in a release
  yet. Check again later, or build from source if it matters.
- **No fix known:** keep it only if you need it.
- **Already patched by Homebrew:** nothing to do.

An item can appear in more than one group when its advisories differ.
A row gives the name, the installed version (and the fixed one, for
Install now), the advisory count and the worst severity. Under it:

- `KNOWN EXPLOITED`: CISA lists the advisory as used in attacks.
- `listening on ...`: it takes connections from beyond this Mac:
  `*:8080` (every address), `3000 on one address`, `443 via tailscale
  serve (tailnet)` or `443 via tailscale funnel (internet)`.
- `(not in use)`: an old version still on disk.
- `(cask)`, `(uv tool)`, `(npm)`: the source, when it is not a formula.

The last lines say how many items were checked, and why the rest were
not, so an empty Install now never reads as all clear.

`--json` prints the data the text is drawn from. Colour appears only on
a terminal, and never with `NO_COLOR` set. `report` exits 1 when there
is no record yet, and 2 when the newest one cannot be read.

## Homebrew's own patches

Homebrew often backports a security fix as a patch to a formula,
without a new upstream version. Matching by version alone would call
that keg exposed. patched reads the installed keg's own copy of its
formula: when a patch that applies on macOS names the advisory, or its
upstream fix commit, the advisory counts as patched by Homebrew. When
the formula cannot be read, the advisory stays exposed.

## The scan record

Each scan saves `~/.patched/scans/HOST-YYYYMMDDTHHMMSS.json`, readable
only by you (mode 600, in a 700 directory), with every item, advisory
and listener by name.

After each scan, records older than 30 days are removed, and the scan
says so (`pruned 3 records older than 30 days`). Each host's newest
record always stays. `PATCHED_KEEP_DAYS` sets the days; `0` keeps every
record. One record is about 300 KB, so an hourly scan writes about
7 MB a day.

`PATCHED_HOME` moves the records and the cache out of `~/.patched`.
