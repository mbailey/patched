"""CISA's Known Exploited Vulnerabilities catalog, cached for a day."""
from __future__ import annotations

import json

from . import net

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def load() -> tuple[set[str], dict]:
    """(CVE ids, {version, count}) from the cache or the feed."""
    path = net.cache_dir("kev") / "kev.json"
    d = net.cached(path, 86400)
    if d is None:
        d = net.get_json(URL)
        net.write_private(path, json.dumps(d))
    cves = {v["cveID"] for v in d.get("vulnerabilities", [])}
    return cves, {"version": d.get("catalogVersion", ""), "count": len(cves)}
