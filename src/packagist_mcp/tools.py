"""Task-shaped Packagist operations. Each function returns trimmed, JSON-serialisable data."""

from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime, timezone
from typing import Any

from .client import PackagistClient, PackagistError, enc
from .versions import expand_minified, is_stable, parse_version, satisfies, sort_key

NAME_RE = re.compile(r"^[a-z0-9]([_.-]?[a-z0-9]+)*/[a-z0-9]([_.-]?[a-z0-9]+)*$")
PLATFORM_RE = re.compile(r"^(php(-64bit|-ipv6|-zts|-debug)?|hhvm|ext-.+|lib-.+|composer(-plugin-api|-runtime-api)?)$", re.I)
ADVISORY_CHUNK = 40
MAX_AUDIT_PACKAGES = 60
MAX_ADVISORIES_PER_PACKAGE = 3


def norm_name(name: str) -> str:
    n = name.strip().lower()
    if not NAME_RE.match(n):
        raise PackagistError(f"'{name}' is not a Composer package name. Expected 'vendor/package', e.g. 'monolog/monolog'.")
    return n


def _day(ts: str | None) -> str | None:
    return ts[:10] if ts else None


def _days_since(ts: str | None) -> int | None:
    if not ts:
        return None
    try:
        when = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max((datetime.now(timezone.utc) - when).days, 0)


def _split_platform(req: dict[str, str] | None) -> tuple[dict[str, str], dict[str, str]]:
    packages, platform = {}, {}
    for k, v in (req or {}).items():
        (platform if PLATFORM_RE.match(k) else packages)[k] = v
    return packages, platform


async def load_versions(client: PackagistClient, name: str) -> list[dict[str, Any]]:
    """All released versions (newest first), with Composer's minified metadata expanded."""
    data = await client.repo(f"/p2/{enc(name.split('/')[0])}/{enc(name.split('/')[1])}.json")
    if not data or name not in data.get("packages", {}):
        raise PackagistError(f"Package '{name}' was not found on Packagist. Use search_packages to find the right name.")
    entries = expand_minified(data["packages"][name])
    return [e for e in entries if not str(e.get("version", "")).startswith("dev-") and not str(e.get("version", "")).endswith("-dev")]


async def load_advisories(client: PackagistClient, names: list[str]) -> dict[str, list[dict[str, Any]]]:
    """Security advisories per package, fetched in chunks."""
    out: dict[str, list[dict[str, Any]]] = {n: [] for n in names}
    chunks = [names[i : i + ADVISORY_CHUNK] for i in range(0, len(names), ADVISORY_CHUNK)]
    results = await asyncio.gather(*[client.api("/api/security-advisories/", {"packages[]": c}) for c in chunks])
    for res in results:
        adv = (res or {}).get("advisories", {})
        if isinstance(adv, list):  # the API returns [] when nothing matches
            continue
        for pkg, items in adv.items():
            out.setdefault(pkg, []).extend(items)
    return out


def _short(text: str | None, limit: int = 140) -> str | None:
    if text and len(text) > limit:
        return text[:limit].rsplit("|", 1)[0] + f"|... ({text.count('|') + 1} ranges in total)"
    return text


def trim_advisory(a: dict[str, Any]) -> dict[str, Any]:
    out = {
        "id": a.get("advisoryId"),
        "title": a.get("title"),
        "cve": a.get("cve"),
        "severity": a.get("severity"),
        "affected": _short(a.get("affectedVersions")),
        "reported": _day(a.get("reportedAt")),
        "link": a.get("link"),
    }
    return {k: v for k, v in out.items() if v is not None}


def affecting(advisories: list[dict[str, Any]], version: str) -> list[dict[str, Any]]:
    return [a for a in advisories if satisfies(version, a.get("affectedVersions") or "") is True]


def _abandoned(entry: dict[str, Any]) -> dict[str, Any] | bool:
    ab = entry.get("abandoned")
    if isinstance(ab, str) and ab:
        return {"replacement": ab}
    return bool(ab)


# ---------------------------------------------------------------------------------------------


async def search_packages(client: PackagistClient, query: str, type: str | None, tags: str | None, per_page: int, page: int) -> dict[str, Any]:
    params: dict[str, Any] = {"q": query, "per_page": per_page, "page": page}
    if type:
        params["type"] = type
    if tags:
        params["tags"] = tags
    data = await client.api("/search.json", params) or {}
    results = []
    for r in data.get("results", []):
        row = {
            "name": r.get("name"),
            "description": (r.get("description") or "")[:200],
            "repository": r.get("repository"),
            "downloads": r.get("downloads"),
            "favers": r.get("favers"),
        }
        if r.get("abandoned"):
            row["abandoned"] = r["abandoned"] if isinstance(r["abandoned"], str) else True
        results.append(row)
    out: dict[str, Any] = {"total": data.get("total", len(results)), "page": page, "results": results}
    if data.get("next"):
        out["next_page"] = page + 1
    return out


async def get_package(client: PackagistClient, name: str) -> dict[str, Any]:
    name = norm_name(name)
    vendor, pkg = name.split("/")
    versions, stats, advisories = await asyncio.gather(
        load_versions(client, name),
        client.api(f"/packages/{enc(vendor)}/{enc(pkg)}/stats.json"),
        load_advisories(client, [name]),
    )
    if not versions:
        raise PackagistError(f"Package '{name}' has no tagged releases (only development branches).")
    stable = [v for v in versions if is_stable(v["version"])]
    ordered = sorted(versions, key=lambda v: sort_key(v["version"]), reverse=True)
    latest = (sorted(stable, key=lambda v: sort_key(v["version"]), reverse=True) or ordered)[0]
    newest = ordered[0]
    deps, platform = _split_platform(latest.get("require"))
    advs = advisories.get(name, [])
    hitting = affecting(advs, latest["version"])
    out: dict[str, Any] = {
        "name": name,
        "description": latest.get("description"),
        "latest_stable": {"version": latest["version"], "released": _day(latest.get("time")), "days_ago": _days_since(latest.get("time"))},
        "abandoned": _abandoned(latest),
        "type": latest.get("type"),
        "license": latest.get("license"),
        "keywords": latest.get("keywords"),
        "homepage": latest.get("homepage"),
        "repository": (latest.get("source") or {}).get("url"),
        "support": latest.get("support"),
        "php_and_extensions": platform or None,
        "runtime_dependencies": deps,
        "versions": {"total": len(versions), "stable": len(stable), "first_release": _day(min((v.get("time") or "" for v in versions), default=None) or None)},
        "downloads": (stats or {}).get("downloads"),
        "security_advisories": {"total": len(advs), "affecting_latest_stable": [trim_advisory(a) for a in hitting]},
    }
    if sort_key(newest["version"]) > sort_key(latest["version"]):
        out["newer_prerelease"] = {"version": newest["version"], "released": _day(newest.get("time"))}
    recent = sorted(advs, key=lambda a: a.get("reportedAt") or "", reverse=True)[:5]
    if recent:
        out["security_advisories"]["most_recent"] = [trim_advisory(a) for a in recent]
    return {k: v for k, v in out.items() if v not in (None, "", [], {})}


async def list_versions(client: PackagistClient, name: str, include_prereleases: bool, limit: int) -> dict[str, Any]:
    name = norm_name(name)
    versions, advisories = await asyncio.gather(load_versions(client, name), load_advisories(client, [name]))
    advs = advisories.get(name, [])
    rows = [v for v in versions if include_prereleases or is_stable(v["version"])]
    rows.sort(key=lambda v: sort_key(v["version"]), reverse=True)
    out_rows = []
    for v in rows[:limit]:
        row: dict[str, Any] = {"version": v["version"], "released": _day(v.get("time"))}
        php = (v.get("require") or {}).get("php")
        if php:
            row["php"] = php
        hit = affecting(advs, v["version"])
        if hit:
            row["advisories"] = [a.get("advisoryId") for a in hit]
        if v.get("abandoned"):
            row["abandoned"] = _abandoned(v)
        out_rows.append(row)
    out: dict[str, Any] = {"package": name, "shown": len(out_rows), "available": len(rows), "versions": out_rows}
    if len(rows) > limit:
        out["note"] = f"{len(rows) - limit} older versions not shown; raise limit to see more."
    return out


async def get_dependencies(client: PackagistClient, name: str, version: str | None, extended: bool = False) -> dict[str, Any]:
    name = norm_name(name)
    versions = await load_versions(client, name)
    if version:
        want = parse_version(version)
        match = next((v for v in versions if v["version"].lstrip("v") == version.lstrip("v") or (want and parse_version(v["version"]) == want)), None)
        if match is None:
            sample = ", ".join(v["version"] for v in versions[:5])
            raise PackagistError(f"Version '{version}' of {name} was not found. Recent versions: {sample}.")
    else:
        stable = [v for v in versions if is_stable(v["version"])] or versions
        match = max(stable, key=lambda v: sort_key(v["version"]))
    req, platform = _split_platform(match.get("require"))
    dev, _ = _split_platform(match.get("require-dev"))
    out = {
        "package": name,
        "version": match["version"],
        "released": _day(match.get("time")),
        "platform": platform,
        "require": req,
        "require_dev": dev if extended else None,
        "suggest": match.get("suggest") if extended else None,
        "conflict": match.get("conflict"),
        "extended_fields_hidden": (None if extended or not (dev or match.get("suggest")) else ["require_dev", "suggest"]),
        "replace": match.get("replace"),
        "provide": match.get("provide"),
    }
    return {k: v for k, v in out.items() if v not in (None, {}, [])}


async def security_advisories(client: PackagistClient, packages: list[str]) -> dict[str, Any]:
    """Each entry is 'vendor/name' or 'vendor/name@1.2.3' (a version splits advisories into affecting / not affecting)."""
    wanted: dict[str, str | None] = {}
    for item in packages:
        pkg, _, ver = item.partition("@")
        wanted[norm_name(pkg)] = ver.strip() or None
    advisories = await load_advisories(client, list(wanted))
    out: dict[str, Any] = {}
    for pkg, ver in wanted.items():
        advs = advisories.get(pkg, [])
        if ver is None:
            out[pkg] = {"advisories": [trim_advisory(a) for a in advs]} if advs else {"advisories": []}
        else:
            hit = affecting(advs, ver)
            unparsed = parse_version(ver) is None
            entry: dict[str, Any] = {"version": ver, "affecting": [trim_advisory(a) for a in hit], "other_advisories": len(advs) - len(hit)}
            if unparsed:
                entry["note"] = f"'{ver}' is not a release version, so advisories could not be matched; showing none as affecting."
            out[pkg] = entry
    vulnerable = [p for p, e in out.items() if e.get("affecting")]
    summary = {"packages": len(out), "with_advisories": sum(1 for e in out.values() if e.get("advisories") or e.get("affecting") or e.get("other_advisories"))}
    if any(v for v in wanted.values()):
        summary["affected_at_given_version"] = vulnerable
    return {"summary": summary, "results": out}


async def audit_requirements(client: PackagistClient, composer_json: str | dict | None, requirements: dict[str, str] | None, include_dev: bool) -> dict[str, Any]:
    reqs: dict[str, str] = {}
    if composer_json:
        try:
            doc = composer_json if isinstance(composer_json, dict) else json.loads(composer_json)
        except ValueError as exc:
            raise PackagistError(f"composer_json is not valid JSON: {exc}") from exc
        if not isinstance(doc, dict):
            raise PackagistError("composer_json must be a JSON object (the contents of a composer.json file).")
        reqs.update(doc.get("require") or {})
        if include_dev:
            for k, v in (doc.get("require-dev") or {}).items():
                reqs.setdefault(k, v)
    if requirements:
        reqs.update(requirements)
    if not reqs:
        raise PackagistError("Nothing to audit: pass composer_json (file contents) or a requirements mapping such as {'monolog/monolog': '^2.0'}.")
    packages, platform = _split_platform(reqs)
    skipped = []
    if len(packages) > MAX_AUDIT_PACKAGES:
        skipped = list(packages)[MAX_AUDIT_PACKAGES:]
        packages = dict(list(packages.items())[:MAX_AUDIT_PACKAGES])
    cons: dict[str, str] = {}
    for n, c in packages.items():
        try:
            cons[norm_name(n)] = str(c)
        except PackagistError:
            skipped.append(n)
    names = list(cons)
    advisories = await load_advisories(client, names)

    async def one(name: str) -> dict[str, Any]:
        constraint = cons[name]
        row: dict[str, Any] = {"package": name, "constraint": constraint}
        try:
            versions = await load_versions(client, name)
        except PackagistError:
            row["status"] = "not_found"
            return row
        stable = sorted((v for v in versions if is_stable(v["version"])), key=lambda v: sort_key(v["version"]), reverse=True)
        if not stable:
            row["status"] = "no_stable_release"
            return row
        latest = stable[0]
        row["latest_stable"] = latest["version"]
        row["released"] = _day(latest.get("time"))
        ab = _abandoned(latest)
        if ab:
            row["abandoned"] = ab
        allowed = [v for v in stable if satisfies(v["version"], constraint) is True]
        if satisfies(latest["version"], constraint) is None:
            row["status"] = "constraint_not_analysed"
            row["note"] = "Constraint uses a branch, alias or stability flag; only latest-version facts are shown."
            installed = latest["version"]
        elif not allowed:
            row["status"] = "no_matching_release"
            installed = None
        else:
            installed = allowed[0]["version"]
            row["newest_allowed"] = installed
            if installed == latest["version"]:
                row["status"] = "up_to_date"
            else:
                a, b = parse_version(installed), parse_version(latest["version"])
                row["status"] = "major_update_blocked" if a and b and a[0][0] != b[0][0] else "update_available"
        if installed:
            hit = affecting(advisories.get(name, []), installed)
            if hit:
                rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
                hit = sorted(hit, key=lambda a: (rank.get(str(a.get("severity")).lower(), 4), a.get("reportedAt") or ""))
                row["advisory_count"] = len(hit)
                row["advisories_at_newest_allowed"] = [trim_advisory(a) for a in hit[:MAX_ADVISORIES_PER_PACKAGE]]
                if len(hit) > MAX_ADVISORIES_PER_PACKAGE:
                    row["advisories_note"] = f"Showing the {MAX_ADVISORIES_PER_PACKAGE} most severe; use security_advisories for all."
        return row

    rows = await asyncio.gather(*[one(n) for n in names])
    order = {"not_found": 0, "no_matching_release": 1, "major_update_blocked": 3, "update_available": 4, "constraint_not_analysed": 5, "no_stable_release": 2, "up_to_date": 6}
    rows = sorted(rows, key=lambda r: (not r.get("advisories_at_newest_allowed"), not r.get("abandoned"), order.get(r.get("status", ""), 9), r["package"]))
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    out: dict[str, Any] = {
        "summary": {
            "packages": len(rows),
            "with_security_advisories": sum(1 for r in rows if r.get("advisories_at_newest_allowed")),
            "abandoned": sum(1 for r in rows if r.get("abandoned")),
            "by_status": counts,
        },
        "packages": rows,
    }
    if platform:
        out["platform_requirements"] = platform
    if skipped:
        out["not_checked"] = skipped
    return out


async def download_stats(client: PackagistClient, name: str, version: str | None, period: str, points: int) -> dict[str, Any]:
    name = norm_name(name)
    vendor, pkg = name.split("/")
    totals = await client.api(f"/packages/{enc(vendor)}/{enc(pkg)}/stats.json")
    if totals is None:
        raise PackagistError(f"Package '{name}' was not found on Packagist.")
    series_path = f"/packages/{enc(vendor)}/{enc(pkg)}/stats/{enc(version) if version else 'all'}.json"
    series = await client.api(series_path, {"average": period})
    if series is None:
        raise PackagistError(f"No download statistics for {name} version '{version}'. Use list_versions for valid versions.")
    labels = series.get("labels", [])
    values = series.get("values", {})
    vals = next(iter(values.values()), []) if isinstance(values, dict) else values
    pairs = list(zip(labels, vals))[-points:]
    return {
        "package": name,
        "totals": totals.get("downloads"),
        "version": version or "all versions",
        "period": period,
        "series": [{"date": d, "downloads": n} for d, n in pairs],
    }


async def list_packages(client: PackagistClient, vendor: str | None, type: str | None, limit: int) -> dict[str, Any]:
    if not vendor and not type:
        raise PackagistError("Give a vendor (e.g. 'symfony') or a package type (e.g. 'phpstan-extension'); the full list has hundreds of thousands of names.")
    params: dict[str, Any] = {"fields[]": ["repository", "abandoned"]}
    if vendor:
        params["vendor"] = vendor.strip().lower()
    if type:
        params["type"] = type
    data = await client.api("/packages/list.json", params) or {}
    pk = data.get("packages", {})
    items = list(pk.items())
    rows = []
    for n, f in items[:limit]:
        row: dict[str, Any] = {"name": n, "repository": f.get("repository")}
        if f.get("abandoned"):
            row["abandoned"] = f["abandoned"] if isinstance(f["abandoned"], str) else True
        rows.append(row)
    out: dict[str, Any] = {"total": len(items), "shown": len(rows), "packages": rows}
    if len(items) > limit:
        out["note"] = f"{len(items) - limit} more not shown; raise limit or use search_packages to narrow down."
    return out
