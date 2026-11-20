"""One scan: collect, match, return the record. Each stage fails alone."""
from __future__ import annotations

import socket
import time
import traceback
from typing import Protocol

from . import allow, brewpatch, collect, kev, osv

COLLECT = ["brew", "apps", "uv", "npm", "listeners", "launchd", "protections", "macos"]


class Progress(Protocol):
    def start(self, name: str) -> None: ...
    def done(self, name: str, ok: bool, seconds: float) -> None: ...


def plan(network: bool = True, update: bool = True) -> list[str]:
    """The stages run() runs, in order: 16 for a full scan."""
    head = ["brew_update"] if update and network else []
    match = ["kev", "osv", "brew_patches"] if network else []
    return head + COLLECT + match + ["tailscale_serve", "link", "allow", "products"]


def host() -> str:
    """This Mac's short host name: the `host/NAME` layer it reads."""
    return socket.gethostname().split(".")[0]


def run(network: bool = True, update: bool = True, progress: Progress | None = None) -> dict:
    started = time.time()
    scan = {"host": host(), "started": started,
            "stamp": time.strftime("%Y%m%dT%H%M%S", time.localtime(started)),
            "stages": {}, "errors": {}, "items": [], "listeners": [], "launchd": [],
            "protections": {}, "macos": {}, "kev": None,
            "notes": ["listeners and launchd: this user's view, no sudo"]}

    def stage(name, fn):
        if progress:
            progress.start(name)
        t0 = time.time()
        try:
            out = fn()
            scan["stages"][name] = True
            return out
        except Exception as e:  # noqa: BLE001 - a broken stage must show, not stop the scan
            scan["stages"][name] = False
            scan["errors"][name] = "".join(traceback.format_exception_only(e)).strip()
            return None
        finally:
            if progress:
                progress.done(name, scan["stages"].get(name, False), time.time() - t0)

    if update and network:
        stage("brew_update", collect.brew_update)
    brew = stage("brew", collect.brew) or ([], set())
    scan["items"] += brew[0]
    scan["items"] += stage("apps", lambda: collect.apps(brew[1])) or []
    scan["items"] += stage("uv", collect.uv_tools) or []
    scan["items"] += stage("npm", collect.npm_globals) or []
    scan["listeners"] = stage("listeners", collect.listeners) or []
    scan["launchd"] = stage("launchd", collect.launchd) or []
    scan["protections"] = stage("protections", collect.protections) or {}
    scan["macos"] = stage("macos", collect.macos) or {}

    if network:
        k = stage("kev", kev.load)
        cves, scan["kev"] = k if k else (set(), None)
        stage("osv", lambda: osv.match(scan["items"], cves))
        # Its own stage, so a failure shows (patched_scan_ok{stage="brew_patches"} 0)
        # and every brew advisory stays "unknown", counted exposed: fail safe.
        stage("brew_patches", lambda: brewpatch.mark(scan["items"]))
    else:
        scan["stages"]["osv"] = False
        scan["errors"]["osv"] = "skipped: --offline"
    served = stage("tailscale_serve", collect.served_ports) or {}
    scan["served_ports"] = served
    stage("link", lambda: collect.link(scan["listeners"], scan["items"], served))
    services, files = stage("allow", lambda: allow.services(scan["host"])) or (None, [])
    scan["allow"] = {"services": services, "files": files, "config": str(allow.config_dir())}
    collect.allow(scan["listeners"], services)
    # The product allow list: None when the stage failed, so the
    # export writes no count for it, never a clean 0.
    scan["allow"]["products"] = stage(
        "products", lambda: allow.match(scan["items"], allow.products(scan["host"])))
    scan["finished"] = time.time()
    return scan
