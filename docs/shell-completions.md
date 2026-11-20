# Shell completions

TAB completes every patched command and option.

Try it in the shell you are in:

```sh
eval "$(patched completions)"
```

Keep it, in bash:

```sh
patched completions --install
```

That writes `~/.local/share/bash-completion/completions/patched` (or
under `$BASH_COMPLETION_USER_DIR`), which bash-completion 2 loads on the
next TAB. Homebrew's `bash-completion@2` provides it.

For zsh or fish, print the script and source it from your shell's
setup: `patched completions zsh`, `patched completions fish`.
`--install` writes the bash script only.
