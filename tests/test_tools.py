import json

import httpx
import pytest
import respx
from mcp import Client

from packagist_mcp import server

BASE = "https://packagist.org"
REPO = "https://repo.packagist.org"


@pytest.fixture(autouse=True)
def fresh(monkeypatch):
    monkeypatch.setenv("PACKAGIST_RETRY_DELAY", "0")
    monkeypatch.delenv("PACKAGIST_BASE_URL", raising=False)
    monkeypatch.delenv("PACKAGIST_REPO_URL", raising=False)
    monkeypatch.delenv("PACKAGIST_MAX_CHARS", raising=False)
    server.client.clear_cache()


async def call(tool, args=None):
    async with Client(server.mcp) as c:
        return await c.call_tool(tool, args or {})


def text(result):
    return "".join(x.text for x in result.content)


def data(result):
    assert not result.is_error, text(result)
    return json.loads(text(result))


def v(version, time, **extra):
    return {"name": "acme/log", "version": version, "version_normalized": version, "time": time, **extra}


# Minified like the real endpoint: later entries only carry changed fields.
LOG_VERSIONS = [
    v("3.1.0", "2026-11-01T10:00:00+00:00", description="Logger", license=["MIT"], type="library", keywords=["log"],
      require={"php": ">=8.1", "ext-json": "*", "psr/log": "^3.0"}, source={"url": "https://github.com/acme/log.git"}),
    {"version": "3.1.0-RC1", "time": "2026-10-20T10:00:00+00:00"},
    {"version": "3.0.0", "time": "2026-06-01T10:00:00+00:00"},
    {"version": "2.5.0", "time": "2025-01-01T10:00:00+00:00", "require": {"php": ">=7.4", "psr/log": "^1.0"}},
    {"version": "dev-main", "time": "2026-11-02T10:00:00+00:00"},
    {"version": "2.x-dev", "time": "2026-11-02T10:00:00+00:00"},
]
ADV = {
    "advisories": {
        "acme/log": [
            {"advisoryId": "PKSA-1", "packageName": "acme/log", "title": "Old header injection", "cve": "CVE-2020-1", "severity": "high",
             "affectedVersions": ">=2.0.0,<2.6.0", "reportedAt": "2020-01-01 00:00:00", "link": "https://example.test/1"},
            {"advisoryId": "PKSA-2", "packageName": "acme/log", "title": "New issue", "severity": "low",
             "affectedVersions": ">=3.0.0,<3.2.0", "reportedAt": "2026-11-03 00:00:00", "link": "https://example.test/2"},
        ]
    }
}


def mock_log(router, advisories=ADV):
    router.get(f"{REPO}/p2/acme/log.json").respond(200, json={"minified": "composer/2.0", "packages": {"acme/log": LOG_VERSIONS}})
    router.get(f"{BASE}/packages/acme/log/stats.json").respond(200, json={"downloads": {"total": 1000, "monthly": 100, "daily": 5}, "versions": []})
    router.get(f"{BASE}/api/security-advisories/").respond(200, json=advisories)


async def test_search_trims_and_pages():
    with respx.mock(assert_all_called=False) as router:
        route = router.get(f"{BASE}/search.json").respond(
            200,
            json={"results": [{"name": "a/b", "description": "x" * 500, "url": "u", "repository": "r", "downloads": 5, "favers": 2, "abandoned": "c/d"}],
                  "total": 40, "next": "https://packagist.org/search.json?page=2"},
        )
        out = data(await call("search_packages", {"query": "log", "type": "library", "per_page": 1}))
        assert route.calls[0].request.url.params["type"] == "library"
    assert out["next_page"] == 2 and out["total"] == 40
    row = out["results"][0]
    assert len(row["description"]) == 200 and row["abandoned"] == "c/d" and "url" not in row


async def test_get_package_combines_three_calls():
    with respx.mock(assert_all_called=False) as router:
        mock_log(router)
        out = data(await call("get_package", {"name": "Acme/Log"}))
    assert out["latest_stable"]["version"] == "3.1.0"
    assert "newer_prerelease" not in out
    assert out["php_and_extensions"] == {"php": ">=8.1", "ext-json": "*"}
    assert out["runtime_dependencies"] == {"psr/log": "^3.0"}
    assert out["versions"] == {"total": 4, "stable": 3, "first_release": "2025-01-01"}
    assert out["downloads"]["monthly"] == 100
    assert out["security_advisories"]["total"] == 2
    assert [a["id"] for a in out["security_advisories"]["affecting_latest_stable"]] == ["PKSA-2"]
    assert out["repository"] == "https://github.com/acme/log.git"


async def test_get_package_not_found_and_bad_name():
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{REPO}/p2/no/pkg.json").respond(404, json={"message": "not found"})
        router.get(f"{BASE}/packages/no/pkg/stats.json").respond(404)
        router.get(f"{BASE}/api/security-advisories/").respond(200, json={"advisories": []})
        r = await call("get_package", {"name": "no/pkg"})
        assert r.is_error and "not found" in text(r)
    r = await call("get_package", {"name": "not a name"})
    assert r.is_error and "vendor/package" in text(r)


async def test_list_versions_flags_advisories_and_hides_prereleases():
    with respx.mock(assert_all_called=False) as router:
        mock_log(router)
        out = data(await call("list_versions", {"name": "acme/log"}))
        assert [r["version"] for r in out["versions"]] == ["3.1.0", "3.0.0", "2.5.0"]
        assert out["versions"][1]["advisories"] == ["PKSA-2"] and out["versions"][2]["advisories"] == ["PKSA-1"]
        assert out["versions"][0]["advisories"] == ["PKSA-2"]
        assert out["versions"][2]["php"] == ">=7.4"
        full = data(await call("list_versions", {"name": "acme/log", "include_prereleases": True, "limit": 2}))
    assert [r["version"] for r in full["versions"]] == ["3.1.0", "3.1.0-RC1"] and "note" in full


async def test_get_dependencies_default_and_version():
    with respx.mock(assert_all_called=False) as router:
        mock_log(router)
        latest = data(await call("get_dependencies", {"name": "acme/log"}))
        old = data(await call("get_dependencies", {"name": "acme/log", "version": "2.5.0"}))
        missing = await call("get_dependencies", {"name": "acme/log", "version": "9.9.9"})
    assert latest["version"] == "3.1.0" and latest["platform"]["php"] == ">=8.1" and latest["require"] == {"psr/log": "^3.0"}
    assert old["require"] == {"psr/log": "^1.0"} and old["platform"] == {"php": ">=7.4"}
    assert missing.is_error and "3.1.0" in text(missing)


async def test_security_advisories_with_versions():
    with respx.mock(assert_all_called=False) as router:
        route = router.get(f"{BASE}/api/security-advisories/").respond(200, json=ADV)
        out = data(await call("security_advisories", {"packages": ["acme/log@2.5.0", "acme/log"]}))
        # the same package twice collapses to the last entry (no version): both forms parse
        assert route.call_count == 1
        both = data(await call("security_advisories", {"packages": ["acme/log@2.5.0"]}))
    assert out["results"]["acme/log"]["advisories"][0]["id"] == "PKSA-1"
    r = both["results"]["acme/log"]
    assert [a["id"] for a in r["affecting"]] == ["PKSA-1"] and r["other_advisories"] == 1
    assert both["summary"]["affected_at_given_version"] == ["acme/log"]


async def test_security_advisories_empty_list_response():
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/api/security-advisories/").respond(200, json={"advisories": []})
        out = data(await call("security_advisories", {"packages": ["acme/clean@1.0.0"]}))
    assert out["results"]["acme/clean"]["affecting"] == [] and out["summary"]["affected_at_given_version"] == []


async def test_advisories_chunked_for_many_packages():
    names = [f"v/p{i}" for i in range(95)]
    with respx.mock(assert_all_called=False) as router:
        route = router.get(f"{BASE}/api/security-advisories/").respond(200, json={"advisories": {}})
        await call("security_advisories", {"packages": names})
    assert route.call_count == 3


def mock_other(router):
    router.get(f"{REPO}/p2/old/abandoned.json").respond(
        200, json={"packages": {"old/abandoned": [{"name": "old/abandoned", "version": "1.2.0", "time": "2019-01-01T00:00:00+00:00", "abandoned": "new/shiny"}]}})
    router.get(f"{REPO}/p2/acme/branchy.json").respond(
        200, json={"packages": {"acme/branchy": [{"name": "acme/branchy", "version": "1.0.0", "time": "2026-01-01T00:00:00+00:00"}]}})
    router.get(f"{REPO}/p2/acme/missing.json").respond(404)


async def test_audit_requirements():
    composer = {
        "require": {"php": "^8.1", "ext-json": "*", "acme/log": "^2.0", "old/abandoned": "^1.0", "acme/branchy": "dev-main", "acme/missing": "^1.0", "Bad Name": "1"},
        "require-dev": {"acme/devtool": "^1"},
    }
    with respx.mock(assert_all_called=False) as router:
        mock_log(router)
        mock_other(router)
        out = data(await call("audit_requirements", {"composer_json": json.dumps(composer)}))
    rows = {r["package"]: r for r in out["packages"]}
    assert "acme/devtool" not in rows
    log = rows["acme/log"]
    assert log["latest_stable"] == "3.1.0" and log["newest_allowed"] == "2.5.0" and log["status"] == "major_update_blocked"
    assert [a["id"] for a in log["advisories_at_newest_allowed"]] == ["PKSA-1"]
    assert rows["old/abandoned"]["abandoned"] == {"replacement": "new/shiny"} and rows["old/abandoned"]["status"] == "up_to_date"
    assert rows["acme/branchy"]["status"] == "constraint_not_analysed"
    assert rows["acme/missing"]["status"] == "not_found"
    assert out["platform_requirements"] == {"php": "^8.1", "ext-json": "*"}
    assert out["not_checked"] == ["Bad Name"]
    assert out["summary"]["with_security_advisories"] == 1 and out["summary"]["abandoned"] == 1
    assert out["packages"][0]["package"] == "acme/log"  # problems first


async def test_audit_accepts_object_and_dev_flag_and_mapping():
    with respx.mock(assert_all_called=False) as router:
        mock_log(router)
        router.get(f"{REPO}/p2/acme/dev.json").respond(404)
        out = data(await call("audit_requirements", {"composer_json": {"require": {}, "require-dev": {"acme/dev": "^1"}}, "include_dev": True, "requirements": {"acme/log": "^3.0"}}))
    rows = {r["package"]: r for r in out["packages"]}
    assert rows["acme/log"]["status"] == "up_to_date" and rows["acme/log"]["advisories_at_newest_allowed"][0]["id"] == "PKSA-2"
    assert rows["acme/dev"]["status"] == "not_found"


async def test_audit_input_errors():
    assert (await call("audit_requirements", {})).is_error
    r = await call("audit_requirements", {"composer_json": "{not json"})
    assert r.is_error and "not valid JSON" in text(r)


async def test_audit_caps_advisories_per_package():
    many = {"advisories": {"acme/log": [
        {"advisoryId": f"PKSA-{i}", "title": "t", "severity": "low" if i else "critical", "affectedVersions": "<3.0.0", "reportedAt": "2026-01-0%d 00:00:00" % (i + 1)}
        for i in range(6)]}}
    with respx.mock(assert_all_called=False) as router:
        mock_log(router, many)
        out = data(await call("audit_requirements", {"requirements": {"acme/log": "^2.0"}}))
    row = out["packages"][0]
    assert row["advisory_count"] == 6 and len(row["advisories_at_newest_allowed"]) == 3
    assert row["advisories_at_newest_allowed"][0]["id"] == "PKSA-0" and "advisories_note" in row


async def test_download_stats():
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/packages/acme/log/stats.json").respond(200, json={"downloads": {"total": 9, "monthly": 3, "daily": 1}})
        route = router.get(f"{BASE}/packages/acme/log/stats/3.1.0.json").respond(
            200, json={"labels": ["d1", "d2", "d3"], "values": {"3.1.0": [1, 2, 3]}, "average": "daily"})
        out = data(await call("download_stats", {"name": "acme/log", "version": "3.1.0", "period": "daily", "points": 2}))
        assert route.calls[0].request.url.params["average"] == "daily"
    assert out["series"] == [{"date": "d2", "downloads": 2}, {"date": "d3", "downloads": 3}] and out["totals"]["total"] == 9


async def test_download_stats_unknown_version():
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/packages/acme/log/stats.json").respond(200, json={"downloads": {"total": 9}})
        router.get(f"{BASE}/packages/acme/log/stats/9.9.9.json").respond(404)
        r = await call("download_stats", {"name": "acme/log", "version": "9.9.9"})
    assert r.is_error and "list_versions" in text(r)


async def test_list_packages_requires_filter_and_truncates():
    r = await call("list_packages", {})
    assert r.is_error and "vendor" in text(r)
    with respx.mock(assert_all_called=False) as router:
        route = router.get(f"{BASE}/packages/list.json").respond(
            200, json={"packages": {f"acme/p{i}": {"repository": f"https://x/{i}", "abandoned": i == 0} for i in range(5)}})
        out = data(await call("list_packages", {"vendor": "Acme", "limit": 2}))
        assert route.calls[0].request.url.params["vendor"] == "acme"
    assert out["total"] == 5 and out["shown"] == 2 and out["packages"][0]["abandoned"] is True and "note" in out


async def test_retry_then_success_and_rate_limit_message(monkeypatch):
    with respx.mock(assert_all_called=False) as router:
        route = router.get(f"{BASE}/search.json").mock(side_effect=[httpx.Response(503), httpx.Response(200, json={"results": [], "total": 0})])
        out = data(await call("search_packages", {"query": "zz"}))
        assert route.call_count == 2 and out["results"] == []
    server.client.clear_cache()
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/search.json").respond(429)
        r = await call("search_packages", {"query": "zz"})
    assert r.is_error and "Rate limited" in text(r)


async def test_network_error_and_cache():
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/search.json").mock(side_effect=httpx.ConnectError("boom"))
        r = await call("search_packages", {"query": "zz"})
        assert r.is_error and "failed" in text(r)
    server.client.clear_cache()
    with respx.mock(assert_all_called=False) as router:
        route = router.get(f"{BASE}/search.json").respond(200, json={"results": [], "total": 0})
        await call("search_packages", {"query": "same"})
        await call("search_packages", {"query": "same"})
        assert route.call_count == 1


async def test_truncation_notice(monkeypatch):
    monkeypatch.setenv("PACKAGIST_MAX_CHARS", "200")
    with respx.mock(assert_all_called=False) as router:
        router.get(f"{BASE}/packages/list.json").respond(200, json={"packages": {f"acme/p{i}": {"repository": "https://example.test/" + "x" * 30} for i in range(20)}})
        r = await call("list_packages", {"vendor": "acme"})
    assert "[truncated" in text(r)


async def test_tool_list_is_read_only():
    async with Client(server.mcp) as c:
        tools = (await c.list_tools()).tools
    assert {t.name for t in tools} == {"search_packages", "get_package", "list_versions", "get_dependencies", "security_advisories", "audit_requirements", "download_stats", "list_packages"}
    assert all(t.annotations and t.annotations.read_only_hint for t in tools)
