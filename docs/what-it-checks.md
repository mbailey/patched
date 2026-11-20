# What it checks

A scan takes an inventory of what is installed, then asks
[OSV](https://osv.dev) and CISA's
[Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
catalog about each item it can name. `patched inventory` runs the
inventory alone, with no network (`--json` for the items).

## Sources

- **brew formula:** every installed keg, old versions too.
- **cask:** every installed cask, and the apps it put down.
- **app:** bundles in `/Applications` and `~/Applications` that no cask
  installed.
- **uv tool:** what `uv tool list` shows.
- **npm:** global npm packages.

Formulae, uv tools and npm packages have a name OSV knows. Casks, apps,
and uv tools installed from a path or a git URL do not: they are listed
and counted, never matched.

An old keg still on disk is flagged **(not in use)** in the report: its
advisories are real, but it is not the version that runs, and a
listener is never tied to it. `brew cleanup` removes it.

## Around the packages

The scan also records, for this user and with no sudo:

- **Listeners:** each TCP port a process of yours listens on, and
  whether it binds only to this Mac (loopback), to one address, or to
  every address. A loopback port that `tailscale serve` or `tailscale
  funnel` puts on the network counts as reachable.
- **Protections:** FileVault, System Integrity Protection, Gatekeeper
  and the application firewall, each on or off.
- **launchd jobs** on disk, and the macOS version and build.

A listener is tied to the item whose files it runs, so an item with an
advisory that also takes connections from beyond this Mac is flagged in
the report.

## Item status

A zero from OSV can mean three things, so every item gets a status:

- **exposed:** at least one advisory matches the installed version.
- **patched:** every matching advisory was fixed by a Homebrew formula
  patch (see [Scan and report](scan-and-report.md)).
- **clean:** OSV knows the package, and nothing matches.
- **empty:** OSV holds nothing for this package.
- **blind:** OSV holds records, but none can be matched to a version.
- **no_key:** patched has no OSV name for it (casks, apps, local tools).

Only *clean* counts as clean. The report's last lines say how many items
fell into each of the last three, so you can see what patched could not
check.
