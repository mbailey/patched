# patched - Makefile. `make` lists the targets; each line with ## is one.

.DEFAULT_GOAL := help
SHELL := /usr/bin/env bash
BUMP ?= patch
# every tracked *.sh, and every tracked file whose FIRST line is a sh/bash shebang
SHELLSCRIPTS := $(shell { git ls-files -z | xargs -0 awk 'FNR==1 && /^\#!\/(usr\/bin\/env )?(ba)?sh/ {print FILENAME}'; git ls-files '*.sh'; } | sort -u)
.PHONY: help install test lint format check build release push

help:  ## this list
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-10s %s\n", $$1, $$2}'

install:  ## put patched on the PATH, editable (uv tool install -e .)
	@uv tool install -e .

test:  ## the pytest suite
	@uv run pytest -q

lint:  ## ruff check; shellcheck on every tracked shell script (see SHELLSCRIPTS)
	@uv run ruff check .
	@if [ -n "$(SHELLSCRIPTS)" ]; then command -v shellcheck >/dev/null || { echo "shellcheck not installed (brew install shellcheck)"; exit 1; }; shellcheck $(SHELLSCRIPTS) && echo "shellcheck: $(words $(SHELLSCRIPTS)) scripts clean"; else echo "shellcheck: no shell scripts"; fi

format:  ## ruff format
	@uv run ruff format .

check: lint test  ## lint, then test

build:  ## wheel + sdist into dist/
	@uv build

release:  ## bump (BUMP=patch|minor|major) or set (VERSION=X.Y.Z), then mirror, changelog, commit, tag
	@uv run python scripts/release.py $(or $(VERSION),$(BUMP))

push:  ## push the branch and the tags to origin (release never pushes; this is the line it printed)
	@git push origin HEAD && git push origin --tags
