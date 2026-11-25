"""MCP server exposing the Packagist public API as a small set of task-shaped tools."""

from __future__ import annotations

import json
import logging
import os
import sys
from typing import Annotated, Any, Literal

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from . import tools
from .client import PackagistClient, PackagistError

MAX_CHARS = 20000
READ_ONLY = ToolAnnotations(read_only_hint=True, open_world_hint=True, idempotent_hint=True)

client = PackagistClient()
mcp = MCPServer(
    "packagist",
    instructions=(
        "PHP package data from Packagist, the Composer registry. Use search_packages to find a package, get_package for a "
        "one-call profile (latest release, licence, dependencies, downloads, advisories, abandoned status), list_versions and "
        "get_dependencies for release history and requirements, security_advisories for known vulnerabilities, and "
        "audit_requirements to check a whole composer.json (what is outdated, blocked, abandoned or vulnerable). Package names "
        "are 'vendor/package'. Read-only, no credentials."
    ),
)


def render(data: Any) -> str:
    text = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    limit = int(os.environ.get("PACKAGIST_MAX_CHARS", MAX_CHARS))
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n[truncated: response was {len(text)} characters; request fewer packages or a smaller limit]"


async def run(coro: Any) -> str:
    try:
        return render(await coro)
    except PackagistError as exc:
        raise ToolError(str(exc)) from exc


@mcp.tool(
    name="search_packages",
    description=(
        "Search Packagist for PHP/Composer packages by keyword. Returns name, short description, repository URL, total downloads, "
        "favourites and an abandoned flag (true, or the replacement package name), sorted by relevance. Optional filters: "
        "type (e.g. 'library', 'symfony-bundle', 'composer-plugin', 'wordpress-plugin') and tags. Use get_package for the full profile of one result."
    ),
    annotations=READ_ONLY,
    structured_output=False,
)
async def search_packages(
    query: Annotated[str, Field(description="Search text, e.g. 'http client' or 'monolog'.")],
    type: Annotated[str | None, Field(description="Composer package type filter, e.g. 'library' or 'symfony-bundle'.")] = None,
    tags: Annotated[str | None, Field(description="Keyword tag filter, e.g. 'psr-3'.")] = None,
    per_page: Annotated[int, Field(description="Results per page.", ge=1, le=100)] = 15,
    page: Annotated[int, Field(description="Page number, starting at 1.", ge=1)] = 1,
) -> str:
    return await run(tools.search_packages(client, query, type, tags, per_page, page))


@mcp.tool(
    name="get_package",
    description=(
        "One-call profile of a Composer package: description, latest stable version with release date and age in days, any newer "
        "pre-release, abandoned status (with replacement), licence, keywords, repository and support links, PHP/extension "
        "requirements, runtime dependencies, download totals (total/monthly/daily), version counts and security advisories "
        "(total, those affecting the latest stable release, and the most recent). Combines three Packagist endpoints and avoids "
        "the very large raw package document. Use list_versions for release history."
    ),
    annotations=READ_ONLY,
    structured_output=False,
)
async def get_package(
    name: Annotated[str, Field(description="Package name as 'vendor/package', e.g. 'laravel/framework'.")],
) -> str:
    return await run(tools.get_package(client, name))


@mcp.tool(
    name="list_versions",
    description=(
        "Release history of a package, newest first: version, release date, PHP constraint, and the IDs of any security advisories "
        "that affect that exact version (or an abandoned marker). Pre-releases are hidden unless requested. Use it to choose a "
        "safe version or to see how often a package ships."
    ),
    annotations=READ_ONLY,
    structured_output=False,
)
async def list_versions(
    name: Annotated[str, Field(description="Package name as 'vendor/package'.")],
    include_prereleases: Annotated[bool, Field(description="Include alpha, beta and RC releases.")] = False,
    limit: Annotated[int, Field(description="Maximum versions to return.", ge=1, le=200)] = 20,
) -> str:
    return await run(tools.list_versions(client, name, include_prereleases, limit))


@mcp.tool(
    name="get_dependencies",
    description=(
        "Requirements of one package version: PHP version and extensions (platform), runtime packages (require), "
        "conflicts, replaces and provides; require-dev and suggestions with extended=true. Defaults to the latest stable release; pass a version such as '2.9.1' for another. "
        "Use it to check PHP compatibility or what installing a package pulls in."
    ),
    annotations=READ_ONLY,
    structured_output=False,
)
async def get_dependencies(
    name: Annotated[str, Field(description="Package name as 'vendor/package'.")],
    version: Annotated[str | None, Field(description="Exact version, e.g. '3.8.0'. Omit for the latest stable.")] = None,
    extended: Annotated[bool, Field(description="Also return require-dev and suggest (can be long).")] = False,
) -> str:
    return await run(tools.get_dependencies(client, name, version, extended))


@mcp.tool(
    name="security_advisories",
    description=(
        "Known security advisories for one or many packages in one call (title, CVE, severity, affected version range, report date, link). "
        "Append '@version' to a package, e.g. 'monolog/monolog@2.9.0', and the advisories are split into those that affect that "
        "version and a count of others, using Composer's range syntax. Data comes from Packagist's advisory database "
        "(GitHub Security Advisories and FriendsOfPHP). An empty result means no known advisories, not proof of safety."
    ),
    annotations=READ_ONLY,
    structured_output=False,
)
async def security_advisories(
    packages: Annotated[list[str], Field(description="Entries like 'vendor/name' or 'vendor/name@1.2.3'.", min_length=1, max_length=100)],
) -> str:
    return await run(tools.security_advisories(client, packages))


@mcp.tool(
    name="audit_requirements",
    description=(
        "Audit a project's dependencies in one call. Pass the text of a composer.json (or a mapping of package to constraint). For each "
        "package it reports the latest stable version, the newest version your constraint allows, whether an update is available or "
        "blocked by a major-version constraint, whether the package is abandoned (and its replacement), and known security advisories "
        "that affect the newest allowed version. Problem packages are listed first. Platform requirements (php, ext-*) are listed separately. "
        "Constraints with branches or aliases (dev-main, 'x as y') are not analysed. It reads constraints, not composer.lock, so installed "
        "versions may differ. Capped at 60 packages."
    ),
    annotations=READ_ONLY,
    structured_output=False,
)
async def audit_requirements(
    composer_json: Annotated[str | dict[str, Any] | None, Field(description="Contents of a composer.json file, as text or a JSON object (reads 'require', and 'require-dev' if include_dev).")] = None,
    requirements: Annotated[dict[str, str] | None, Field(description="Alternative: {'vendor/package': 'constraint'}.")] = None,
    include_dev: Annotated[bool, Field(description="Also audit 'require-dev' from composer_json.")] = False,
) -> str:
    return await run(tools.audit_requirements(client, composer_json, requirements, include_dev))


@mcp.tool(
    name="download_stats",
    description=(
        "Download counts for a package: all-time, monthly and daily totals plus a time series. Series is for all versions, or one "
        "version if given, with daily or monthly points (most recent N). Useful for adoption trends and for how fast a new release is rolling out."
    ),
    annotations=READ_ONLY,
    structured_output=False,
)
async def download_stats(
    name: Annotated[str, Field(description="Package name as 'vendor/package'.")],
    version: Annotated[str | None, Field(description="Single version such as '3.13.0'; omit for all versions combined.")] = None,
    period: Annotated[Literal["monthly", "daily"], Field(description="Point granularity.")] = "monthly",
    points: Annotated[int, Field(description="Number of most recent points.", ge=1, le=120)] = 12,
) -> str:
    return await run(tools.download_stats(client, name, version, period, points))


@mcp.tool(
    name="list_packages",
    description=(
        "List package names by vendor ('symfony', 'laravel') or by Composer package type ('phpstan-extension', 'composer-plugin'), "
        "with repository URL and abandoned flag. Use it to survey a vendor's packages; for keyword discovery use search_packages."
    ),
    annotations=READ_ONLY,
    structured_output=False,
)
async def list_packages(
    vendor: Annotated[str | None, Field(description="Vendor prefix, e.g. 'monolog'.")] = None,
    type: Annotated[str | None, Field(description="Composer package type, e.g. 'phpstan-extension'.")] = None,
    limit: Annotated[int, Field(description="Maximum packages returned.", ge=1, le=500)] = 100,
) -> str:
    return await run(tools.list_packages(client, vendor, type, limit))


def main() -> None:
    logging.basicConfig(stream=sys.stderr, level=os.environ.get("LOG_LEVEL", "WARNING").upper())
    transport = os.environ.get("MCP_TRANSPORT", "stdio")
    if transport == "stdio":
        mcp.run("stdio")
    else:
        mcp.run(transport, host=os.environ.get("MCP_HOST", "127.0.0.1"), port=int(os.environ.get("MCP_PORT", "8000")))


if __name__ == "__main__":
    main()
