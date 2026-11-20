# Hourly schedule

`patched schedule on` runs `patched scan --quiet` every hour at :07,
and once when it loads, as a **user LaunchAgent**: no sudo, and nothing
outside your home folder. Nothing is scheduled until you run it.

```sh
patched schedule on -n   # print the agent's plist; change nothing
patched schedule on      # write it and load it
patched schedule status
patched schedule off     # unload it and remove the plist
```

## What it runs

The agent runs the `patched` found on your PATH when you ran `on`, by
its full path, with your PATH from then (plus `~/.local/bin`,
Homebrew's `bin` and the system folders). launchd's own PATH has none
of those, and a tool patched cannot find reads as an empty source, so
`on` warns about any tool the agent would miss. The `PATCHED_*` and
`HOMEBREW_PREFIX` variables set then are carried too.

Changed your PATH or one of those variables? Run `on` again: it
reloads. With nothing changed, a second `on` (or `off`) does nothing.

## Status

`patched schedule status` says whether the agent is loaded, how many
times it ran and its last exit code; the plist and the program it
runs; the log, `~/Library/Logs/patched/scan.log`, and its last line;
the last scan (the newest record, by hand or by the agent); when the
metrics file was written; and any drift between your PATH or variables
now and those the agent carries.

## Good to know

- A user agent runs only while you are logged in. A scan missed while
  the Mac slept runs when it wakes.
- `-q` keeps the log short: the summary line, what was written, and how
  many old records were pruned.
- Each scheduled scan prunes old records, as any scan does: see
  [Scan and report](scan-and-report.md).
