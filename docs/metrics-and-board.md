# Metrics and board

patched works without any of this. If you run
[Prometheus](https://prometheus.io) through
[node_exporter](https://github.com/prometheus/node_exporter), each scan
also writes its numbers as metrics, and a Grafana board and alert rules
come with the repo.

## The metrics file

A scan writes `patched.prom` into node_exporter's textfile directory,
`$(brew --prefix)/var/lib/node_exporter/textfile_collector` unless you
name another (`--textfile-dir`, or `PATCHED_TEXTFILE_DIR`). When the
default directory does not exist, the scan says so and skips the file;
a directory you named that does not exist is an error (exit 2).

By default the file holds **counts only**, so a Prometheus you share
never learns the names of what is vulnerable on your Mac. `--detail`
(or `PATCHED_DETAIL_SERIES=1`) adds series that name advisories,
products and listeners. The scan record always has the names.

`patched scan -n` prints the file and writes nothing. Each series has
its own HELP line.

## Setting it all up

`scripts/bootstrap.sh` installs node_exporter, Prometheus and Grafana
from Homebrew, as your own user (never sudo), each a `brew services`
LaunchAgent bound to 127.0.0.1. Prometheus scrapes node_exporter and
loads patched's alert rules; Grafana gets the Prometheus datasource and
the patched board.

```sh
scripts/bootstrap.sh --dry-run   # print every step, change nothing
scripts/bootstrap.sh             # do it; asks first
```

It is safe to run again: a file that is already right is left alone.
It will not replace a Prometheus or Grafana setup it did not write: it
stops (exit 3) before installing anything. `--force` replaces such
files, keeping each as `FILE.bak-YYYYMMDD`. It never writes through a
symlink. Run it logged in at the screen: `brew services` needs a GUI
session.

Then open the board at <http://127.0.0.1:3000/d/patched>. The first
login is admin/admin, and Grafana asks you to change it. The panels
that name things stay empty until a scan writes names (`--detail`).

## The board

Three rows. **Install now** asks "is there something we need to be
installing?": how many items in use a release fixes, and which.
**Overview**: alerts, exposure, listeners and what the allow lists
flag. **Detail**: the names, empty unless scans run with `--detail`.

## Alert rules

`prometheus/patched.rules.yml` holds these. Each one's summary says
where to look.

- **Scanning:** PatchedStale (no scan for a while), PatchedMissing (no
  metrics at all), PatchedStageFailed (a step failed: its numbers are
  missing, not zero), PatchedBlindSpotsGrew (unmatched items rose 20%
  in a day).
- **Exposure:** PatchedKnownExploited, PatchedKnownExploitedUnusedKeg,
  PatchedCriticalExposed, PatchedExposedListening.
- **Allow lists:** PatchedUnexpectedListener, PatchedUnexpectedProduct,
  PatchedAllowlistNotLoaded, PatchedAllowlistErrors.
- **The Mac:** PatchedProtectionOff (FileVault, SIP, Gatekeeper or the
  firewall is off).
