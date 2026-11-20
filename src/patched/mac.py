"""Where Homebrew lives on this Mac, and whether this is a Mac at all.

Neither question runs a program: both are answered from the environment
and the file system, so they are cheap enough to ask at import.
"""
from __future__ import annotations

import os
import platform
import sys
from collections.abc import Mapping
from pathlib import Path

APPLE_SILICON = Path("/opt/homebrew")  # Homebrew's prefix on Apple silicon
INTEL = Path("/usr/local")  # and on an Intel Mac


def brew_prefix(env: Mapping[str, str] | None = None) -> Path:
    """$HOMEBREW_PREFIX if set; else the prefix whose bin/brew exists, Apple
    silicon's first, then Intel's; else Apple silicon's. Never runs brew."""
    env = os.environ if env is None else env
    if env.get("HOMEBREW_PREFIX"):
        return Path(env["HOMEBREW_PREFIX"])
    for prefix in (APPLE_SILICON, INTEL):
        if (prefix / "bin" / "brew").exists():
            return prefix
    return APPLE_SILICON


def system() -> tuple[str, str]:
    """(sys.platform, the system's own name): ("darwin", "Darwin") on a Mac."""
    return sys.platform, platform.system()


def off_macos() -> str | None:
    """The one line `scan` and `schedule on` stop with off macOS; None on a Mac."""
    plat, name = system()
    if plat == "darwin":
        return None
    return f"patched scans macOS only for now; this is {name or plat}."
