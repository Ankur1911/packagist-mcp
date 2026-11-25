# packagist-mcp

A [Model Context Protocol](https://modelcontextprotocol.io) server for [Packagist](https://packagist.org), the main registry for PHP and Composer packages. It needs no API key and is read-only.

The tools are shaped around common dependency questions rather than one tool per endpoint. `get_package` merges three endpoints (package metadata, download counts, security advisories) into one trimmed profile instead of the 200 KB raw package document. `audit_requirements` takes a whole `composer.json` and reports, per package, the latest stable release, the newest release your constraint allows, whether an update is blocked by a major version, abandoned status with the replacement, and known advisories that affect the version you would actually get. Packagist's minified version metadata is expanded for you, and Composer constraint syntax (`^`, `~`, wildcards, ranges, `||`) is evaluated locally.

## Setup

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/Ankur1911/packagist-mcp && cd packagist-mcp
uv sync
uv run packagist-mcp          # stdio transport
```

Add it to any MCP client that launches stdio servers:

```json
{
  "mcpServers": {
    "packagist": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/packagist-mcp", "packagist-mcp"]
    }
  }
}
```

For HTTP instead of stdio: `MCP_TRANSPORT=streamable-http MCP_HOST=127.0.0.1 MCP_PORT=8000 uv run packagist-mcp`.

## Tools

All tools are read-only.

| Tool | What it returns |
|---|---|
| `search_packages` | Keyword search with optional `type` and `tags` filters: name, short description, repository, downloads, favourites, abandoned flag (or replacement). Paged. |
| `get_package` | One-call profile: latest stable version with date and age, newer pre-release if any, abandoned status and replacement, licence, keywords, repository and support links, PHP and extension requirements, runtime dependencies, download totals, version counts, and security advisories (total, those affecting the latest stable release, most recent). |
| `list_versions` | Release history, newest first: version, date, PHP constraint, and the IDs of advisories that affect that exact version. Pre-releases hidden unless requested. |
| `get_dependencies` | Requirements of one version (latest stable by default): PHP and extensions, runtime packages, conflicts, replaces, provides; `extended=true` adds require-dev and suggest. |
| `security_advisories` | Advisories for 1 to 100 packages in one call. Write `vendor/name@2.9.0` to split results into those affecting that version and a count of the rest. |
| `audit_requirements` | Audit a whole `composer.json` (text or object) or a `{package: constraint}` mapping. Problem packages come first; platform requirements (`php`, `ext-*`) are listed separately; `include_dev` adds `require-dev`. |
| `download_stats` | Total, monthly and daily counts plus a series (monthly or daily, all versions or one version). |
| `list_packages` | Package names for a vendor (`symfony`) or a Composer type (`phpstan-extension`), with repository and abandoned flag. |

## Configuration

All optional environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `PACKAGIST_BASE_URL` | `https://packagist.org` | Packagist API root (for a mirror) |
| `PACKAGIST_REPO_URL` | `https://repo.packagist.org` | Composer metadata host |
| `PACKAGIST_TIMEOUT` | `20` | Request timeout in seconds |
| `PACKAGIST_RETRIES` | `2` | Retries on HTTP 429, 502, 503, 504 and timeouts |
| `PACKAGIST_CONCURRENCY` | `4` | Maximum simultaneous requests |
| `PACKAGIST_CACHE_TTL` | `300` | Seconds to cache identical requests in memory (`0` disables) |
| `PACKAGIST_MAX_CHARS` | `20000` | Responses longer than this are cut with a notice |
| `MCP_TRANSPORT` | `stdio` | `stdio` or `streamable-http` |

## Limits

- Public packages on packagist.org only. Private repositories and Private Packagist need credentials, which this server does not handle.
- `audit_requirements` works from constraints, not `composer.lock`, so the version your project has installed may differ from the "newest allowed" version reported. Constraints that use branches, aliases or stability flags (`dev-main`, `1.x-dev`, `^1.0 as 2.0`) are not analysed; only the latest-release facts are shown. It checks at most 60 packages per call and considers stable releases only.
- Constraint matching covers the common Composer syntax. Unusual constraints may be reported as not analysed rather than guessed.
- Advisory data comes from Packagist's database (GitHub Security Advisories and FriendsOfPHP). No advisories found does not mean a package is safe. Advisory ranges are shortened in output when very long.
- Packagist is a free public service. The server identifies itself with a User-Agent, limits concurrency and caches briefly, but it does not queue requests. Download counts are updated by Packagist on its own schedule.
- Response size is capped (see `PACKAGIST_MAX_CHARS`).

## Development

```bash
uv sync
uv run pytest
```

Tests mock all HTTP traffic with `respx`; no network access is needed.

## Licence

MIT. Author: Ankur Kapuriya. Not affiliated with or endorsed by Packagist or Private Packagist. Check Packagist's terms of use before heavy automated use.
