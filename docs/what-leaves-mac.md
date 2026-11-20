# What leaves your Mac

patched reads your Mac and tells only you. Its record, its cache and
its allow lists stay in `~/.patched`, readable only by you. Three kinds
of network call leave the Mac, and `patched scan --offline` makes none
of them.

## OSV: package names and versions

To match advisories, patched asks [OSV](https://osv.dev)'s public API,
`api.osv.dev`:

1. Which of these packages it knows: the **ecosystem and name** of
   each formula, uv tool and npm package (not casks, apps or local
   tools, which have no OSV name).
2. For each package it knows: the advisories that match the
   **installed version**.
3. The full record of each advisory found, by its id.

So OSV sees which packages are installed, at which versions. It does
not see your host name, your user name, your listeners, your
protections or anything else from the scan. The version match is asked
on every scan; which packages OSV knows is cached in `~/.patched/cache`
for a day, and each advisory's record until OSV says it changed.

## CISA: the known-exploited catalog

patched downloads the whole catalog of
[known exploited vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
from `www.cisa.gov`, at most once a day, and checks it locally. Nothing
about your Mac is sent.

## Homebrew: brew update

A scan starts with `brew update`, which refreshes Homebrew's index from
Homebrew's own servers, as it does when you run it yourself. It installs
nothing. `--no-update` skips it.

## Nothing else

patched sends no telemetry and has no account. It identifies itself to
OSV and CISA by a User-Agent naming patched and its repo, and nothing
more. The metrics file, if you use one, is written locally for your own
node_exporter, with counts only unless you ask for names (see [Metrics
and board](metrics-and-board.md)).
