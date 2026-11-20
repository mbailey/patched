"""Match items against OSV, by four rules.

1. A zero is clean, empty or blind. One versionless query per package says
   whether OSV holds it at all (empty if not). A GIT repo whose records
   carry no tag list for it can't be version-matched (blind).
2. The version comes from the key's own ecosystem (collect.py does this).
3. Advisories are counted after merging aliases (curl's feed and NVD
   publish one record each per CVE).
4. OSV's own matcher decides; we never fit ranges ourselves. We read
   ranges only to name the fixed version for the `patch` label, and the
   upstream fix commits (`fix_commits`) a commit-only fix and brew's
   backported patches are matched by.
"""
from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import cvss, net

API = "https://api.osv.dev/v1"
DAY = 86400
HEX = re.compile(r"^[0-9a-f]{7,40}$")
STAMP = re.compile(r"^(?P<s>[^.Z]+)(?:\.(?P<f>\d+))?Z?$")


def stamp(t: str | None) -> str | None:
    """OSV's `modified` to the microsecond: querybatch cuts the record's nanoseconds.

    The record says 08.635811757Z and querybatch says 08.635811Z for the same
    edit, so a string compare never matched and every scan refetched every
    advisory (about 10 s of a 13 s scan).
    """
    m = STAMP.match(t or "")
    return f"{m['s']}.{(m['f'] or '').ljust(6, '0')[:6]}" if m else t


def vkey(v: str) -> list:
    """A loose version order: digits as ints, so 1.20.17 > 1.20.9."""
    return [int(x) for x in re.findall(r"\d+", v)]


def _pkg(key: list) -> dict:
    return {"name": key[1], "ecosystem": key[0]}


def _batch(queries: list[dict]) -> list[list[dict]]:
    """querybatch, following each query's next_page_token. Returns [{id, modified}] per query."""
    results: list[list[dict]] = [[] for _ in queries]
    pending = list(range(len(queries)))
    tokens: dict[int, str] = {}
    while pending:
        nxt = []
        for i in range(0, len(pending), 500):
            chunk = pending[i:i + 500]
            body = {"queries": [dict(queries[j], **({"page_token": tokens[j]} if j in tokens else {}))
                                for j in chunk]}
            for j, r in zip(chunk, net.post_json(f"{API}/querybatch", body)["results"]):
                results[j] += r.get("vulns", [])
                if r.get("next_page_token"):
                    tokens[j] = r["next_page_token"]
                    nxt.append(j)
        pending = nxt
    return results


def _known(pkgs: list[tuple]) -> dict[tuple, bool]:
    """Does OSV hold any record for each package? Cached a day."""
    out, ask = {}, []
    for p in pkgs:
        hit = net.cached(net.cache_dir("known") / net.cache_key(*p), DAY)
        if hit is None:
            ask.append(p)
        else:
            out[p] = bool(hit["known"])
    if ask:
        # One page of ids is enough to tell empty from known.
        body = {"queries": [{"package": {"name": p[1], "ecosystem": p[0]}} for p in ask]}
        for p, r in zip(ask, net.post_json(f"{API}/querybatch", body)["results"]):
            out[p] = bool(r.get("vulns"))
            net.write_private(net.cache_dir("known") / net.cache_key(*p), json.dumps({"known": out[p]}))
    return out


def _all_records(pkg: tuple) -> list[dict]:
    """Every record for a package (versionless, full), cached a day."""
    path = net.cache_dir("records") / net.cache_key(*pkg)
    hit = net.cached(path, DAY)
    if hit is not None:
        return hit
    recs, tok = [], None
    while True:
        body = {"package": {"name": pkg[1], "ecosystem": pkg[0]}, **({"page_token": tok} if tok else {})}
        r = net.post_json(f"{API}/query", body)
        recs += r.get("vulns", [])
        tok = r.get("next_page_token")
        if not tok:
            break
    net.write_private(path, json.dumps(recs))
    return recs


def _norm_repo(u: str) -> str:
    return (u or "").rstrip("/").removesuffix(".git")


def is_blind(recs: list[dict], repo: str) -> bool:
    """True if no record carries a tag list for this repo: version queries can't hit."""
    for r in recs:
        for a in r.get("affected", []):
            if a.get("versions") and any(_norm_repo(g.get("repo")) == repo for g in a.get("ranges", [])):
                return False
    return True


def _vuln(vid: str, modified: str | None) -> dict:
    """The full record, cached until OSV says it changed."""
    path = net.cache_dir("vulns") / (re.sub(r"[^A-Za-z0-9._-]", "_", vid) + ".json")
    try:
        rec = json.loads(path.read_text())
        if modified is None or stamp(rec.get("modified")) == stamp(modified):
            return rec
    except (OSError, ValueError):
        pass
    rec = net.get_json(f"{API}/vulns/{vid}")
    net.write_private(path, json.dumps(rec))
    return rec


def fixed_version(rec: dict, key: list) -> str | None:
    """The lowest stated fix above our version, for this package; None if no release fixes it."""
    eco, name, ver = key
    fixes = []
    for a in rec.get("affected", []):
        pkg = a.get("package") or {}
        for g in a.get("ranges", []):
            if eco == "GIT":
                if _norm_repo(g.get("repo")) != name:
                    continue
                for x in (g.get("database_specific") or {}).get("extracted_events", []):
                    fixes += [e["fixed"] for e in x.get("range", []) if "fixed" in e]
            elif pkg.get("name") == name and pkg.get("ecosystem", "").lower() == eco.lower():
                fixes += [e["fixed"] for e in g.get("events", []) if "fixed" in e]
    good = [f for f in fixes if not HEX.match(f) and vkey(f) and vkey(f) > vkey(ver)]
    return min(good, key=vkey) if good else None


def fix_commits(rec: dict, repo: str | None) -> list[str]:
    """Upstream fix commits for this repo: every hex `fixed` in the GIT ranges, from
    both `events` and `database_specific.extracted_events` (OSS-Fuzz records carry
    theirs in `events` only). Sorted, unique, lower case."""
    if not repo:
        return []
    out = set()
    for a in rec.get("affected", []):
        for g in a.get("ranges", []):
            if g.get("type") != "GIT" or _norm_repo(g.get("repo")) != _norm_repo(repo):
                continue
            events = list(g.get("events", []))
            for x in (g.get("database_specific") or {}).get("extracted_events", []):
                events += x.get("range", [])
            out |= {e["fixed"].lower() for e in events if HEX.match(str(e.get("fixed", "")).lower())}
    return sorted(out)


def group(recs: list[dict]) -> dict[str, list[dict]]:
    """Records merged by alias: the name is the lowest CVE id, else the record's id."""
    groups: dict[str, list[dict]] = {}
    for r in recs:
        ids = {r["id"], *r.get("aliases", []), *r.get("upstream", [])}
        cves = sorted(i for i in ids if i.startswith("CVE-"))
        groups.setdefault(cves[0] if cves else r["id"], []).append(r)
    return groups


def match(items: list[dict], kev: set[str], workers: int = 8) -> None:
    """Fill each keyed item's `status` (clean|exposed|empty|blind) and `advisories`."""
    keyed = [i for i in items if i.get("key")]
    pkgs = sorted({(i["key"][0], i["key"][1]) for i in keyed})
    known = _known(pkgs)
    queries = sorted({tuple(i["key"]) for i in keyed if known.get((i["key"][0], i["key"][1]))})
    hits = dict(zip(queries, _batch([{"package": _pkg(list(q)), "version": q[2]} for q in queries])))

    # Blind: GIT repos OSV knows, where every version we hold came back 0.
    zero = sorted(p for p in pkgs if p[0] == "GIT" and known.get(p)
                  and not any(hits.get(q) for q in queries if q[:2] == p))
    with ThreadPoolExecutor(workers) as ex:
        blind = {p for p, recs in zip(zero, ex.map(_all_records, zero)) if is_blind(recs, p[1])}
        ids = sorted({(v["id"], v.get("modified")) for vs in hits.values() for v in vs})
        recs = dict(zip([i for i, _ in ids], ex.map(lambda t: _vuln(*t), ids)))

    for it in keyed:
        p, q = (it["key"][0], it["key"][1]), tuple(it["key"])
        if not known.get(p):
            it["status"] = "empty"
        elif p in blind:
            it["status"] = "blind"
        else:
            advs = []
            for name, rs in group([recs[v["id"]] for v in hits.get(q, [])]).items():
                aliases = sorted({a for r in rs for a in (r["id"], *r.get("aliases", []))})
                fixes = [f for r in rs if (f := fixed_version(r, it["key"]))]
                repo = it["key"][1] if it["key"][0] == "GIT" else (it.get("ids") or {}).get("git")
                advs.append({
                    "advisory": name, "ids": aliases,
                    "summary": next((r.get("summary") for r in rs if r.get("summary")), ""),
                    "severity": cvss.worst(*(cvss.severity(r) for r in rs)),
                    "kev": any(a in kev for a in aliases),
                    "fixed": min(fixes, key=vkey) if fixes else None,
                    "fix_commits": sorted({c for r in rs for c in fix_commits(r, repo)}),
                    # brewpatch.mark, its own stage, decides; until then (or if it fails) unknown
                    "patched_by_brew": "unknown" if it.get("source") == "brew-formula" else "n/a",
                })
            it["advisories"] = sorted(advs, key=lambda a: a["advisory"])
            it["status"] = "exposed" if advs else "clean"
    for it in items:
        if not it.get("key"):
            it["status"] = "no_key"


def records_path() -> Path:
    return net.cache_dir("records")
