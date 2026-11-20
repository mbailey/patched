# Allow lists

An allow list says what you expect on a Mac. patched then flags what is
not on it: a package nobody meant to install, or a program listening
where it should not. You do not need one to scan; without one, nothing
is flagged.

There are two lists: **products** (what may be installed) and
**services** (what may listen).

## Where they live

Allow lists are configuration, so they belong in a git repo of your
own. Point `~/.patched/config` at a checkout of it (a symlink), or set
`PATCHED_CONFIG`. Inside, three layers, each a directory:

```text
fleet/              every Mac
class/NAME/         every Mac of one class
host/NAME/          one Mac, by its host name
host/NAME/class     names that Mac's class (one word)
```

What is allowed is the union of the three layers. There are no deny
lines.

## Products: a Brewfile and apps

Each layer may hold a `Brewfile`, in Homebrew's own format:

```ruby
brew "jq"  # we use it
cask "firefox"
uv "ruff"
npm "prettier"
```

patched reads it as text and never runs it: a line with Ruby in it
allows nothing and is reported. A formula that another one needs comes
along with it, so you list only what you asked for.

Apps that no cask installed go in an `apps` file, one name a line:

```text
Xcode  # from the App Store
```

`patched allow` prints every line, merged across the layers, with the
file and line it came from (`--host NAME` for another Mac, `--json` for
data). It exits 1 if a line cannot be read.

`patched allow check` lists what is installed on this Mac and not
allowed, by source. `patched allow diff FILE` compares a Brewfile (from
`brew bundle dump`, say) against the list.

## Services: what may listen

A `services` file in a layer, one line a listener:

```text
sshd any  # remote login
node served  # the dev server, behind tailscale serve
```

A line is a process name and where it binds: `any` (every address),
`address` (one address), `served` or `funnel` (behind `tailscale serve`
or `funnel`). Lines are keyed on process and bind, never on port, since
some programs move ports. Loopback needs no line. Delete a line to stop
allowing it.

With no `services` file in any layer, patched reads a single list at
`~/.patched/allow/services` instead (or the file `PATCHED_ALLOW_SERVICES`
names), in the same format. Once a layer has entries, the layers win.

A listener that is not allowed is counted in the metrics and raises an
alert (see [Metrics and board](metrics-and-board.md)).
