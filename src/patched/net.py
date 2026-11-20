"""HTTP and the cache: urllib only. Network goes to api.osv.dev and www.cisa.gov."""
from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

UA = "patched/0.1 (+https://github.com/mbailey/patched)"
HOME = Path(os.environ.get("PATCHED_HOME", Path.home() / ".patched"))


def private_dir(path: Path) -> Path:
    """mkdir -p with mode 700: the cache and scans map a host's weak points."""
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def cache_dir(*parts: str) -> Path:
    """~/.patched/cache/<parts>, every level 700: the cache says what is installed."""
    path = private_dir(HOME)
    for part in ("cache", *parts):
        path = private_dir(path / part)
    return path


def _fetch(req: urllib.request.Request, timeout: float, tries: int = 3) -> dict:
    """JSON from req; retries a timeout, a dropped connection or a 429/5xx, with backoff."""
    for n in range(tries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code != 429 and e.code < 500 or n == tries - 1:
                raise
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            if n == tries - 1:
                raise
        time.sleep(2 ** n)
    raise AssertionError("unreachable")


def post_json(url: str, body: dict, timeout: float = 120) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "User-Agent": UA},
    )
    return _fetch(req, timeout)


def get_json(url: str, timeout: float = 120) -> dict:
    return _fetch(urllib.request.Request(url, headers={"User-Agent": UA}), timeout)


def cache_key(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode()).hexdigest()[:32]


def cached(path: Path, max_age: float) -> dict | list | None:
    """The cached JSON at path if younger than max_age seconds, else None."""
    try:
        if time.time() - path.stat().st_mtime < max_age:
            return json.loads(path.read_text())
    except (OSError, ValueError):
        pass
    return None


def write_private(path: Path, text: str) -> None:
    """Write text with mode 600, via a temp file and a rename."""
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.replace(tmp, path)
