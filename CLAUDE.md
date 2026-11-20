# patched: standing orders

This repo is bound for the public. A stranger will read every file and
every commit, so it describes the tool, never the home it was built in.

- No home host name, tailnet name, user path, person's or agent's name,
  voice quote or personal inventory in code, tests, docs or commit
  messages.
- Tests use neutral names: the scanned host is `host1`, a second host
  `host2`, the git host `git.example` (`git.example:git/repos/p.git`), a
  user path `/Users/someone`.
- State reasons plainly ("counts only, so a shared Prometheus never holds
  names"). Who decided, when, and in which review lives outside the repo:
  no rulings, review labels or timestamps as provenance.
- Install from the repo (`uv tool install git+https://github.com/mbailey/patched`,
  or `uv tool install .` in a checkout); the `patched` name on PyPI is
  another project's.
