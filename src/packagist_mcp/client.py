"""Small async client for the Packagist public API (no authentication needed)."""

from __future__ import annotations

import asyncio
import os
import time
from typing import Any
from urllib.parse import quote

import httpx

DEFAULT_BASE_URL = "https://packagist.org"
DEFAULT_REPO_URL = "https://repo.packagist.org"
RETRY_STATUSES = {429, 502, 503, 504}


class PackagistError(Exception):
    """An API or network failure with a message that is safe to show a model."""


def enc(value: str) -> str:
    """Percent-encode one path segment."""
    return quote(str(value), safe="")


def _float_env(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


class PackagistClient:
    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._sem: asyncio.Semaphore | None = None
        self._cache: dict[str, tuple[float, Any]] = {}

    @property
    def base_url(self) -> str:
        return os.environ.get("PACKAGIST_BASE_URL", DEFAULT_BASE_URL).rstrip("/")

    @property
    def repo_url(self) -> str:
        return os.environ.get("PACKAGIST_REPO_URL", DEFAULT_REPO_URL).rstrip("/")

    def clear_cache(self) -> None:
        self._cache.clear()

    def _http(self) -> httpx.AsyncClient:
        loop = asyncio.get_running_loop()
        if self._client is None or self._client.is_closed or self._loop is not loop:
            self._loop = loop
            self._sem = asyncio.Semaphore(int(_float_env("PACKAGIST_CONCURRENCY", 4)))
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(_float_env("PACKAGIST_TIMEOUT", 20.0), connect=10.0),
                headers={"Accept": "application/json", "User-Agent": "packagist-mcp/0.1 (open-source MCP server)"},
                follow_redirects=True,
            )
        return self._client

    async def get(self, url: str, params: Any = None) -> Any:
        """GET a full URL and return decoded JSON, or None on 404. Results are cached briefly."""
        ttl = _float_env("PACKAGIST_CACHE_TTL", 300.0)
        key = url + "?" + repr(sorted(params.items()) if isinstance(params, dict) else params)
        hit = self._cache.get(key)
        if hit and ttl > 0 and time.monotonic() - hit[0] < ttl:
            return hit[1]
        data = await self._fetch(url, params)
        if ttl > 0:
            self._cache[key] = (time.monotonic(), data)
        return data

    async def _fetch(self, url: str, params: Any) -> Any:
        retries = int(_float_env("PACKAGIST_RETRIES", 2))
        delay = _float_env("PACKAGIST_RETRY_DELAY", 1.0)
        resp: httpx.Response | None = None
        http = self._http()
        assert self._sem is not None
        for attempt in range(retries + 1):
            try:
                async with self._sem:
                    resp = await http.get(url, params=params)
            except httpx.TimeoutException as exc:
                if attempt < retries:
                    await asyncio.sleep(delay * 2**attempt)
                    continue
                raise PackagistError(f"GET {url} timed out ({type(exc).__name__}). Packagist may be slow; retry later.") from exc
            except httpx.HTTPError as exc:
                raise PackagistError(f"GET {url} failed: {type(exc).__name__}: {exc}") from exc
            if resp.status_code in RETRY_STATUSES and attempt < retries:
                wait = delay * 2**attempt
                retry_after = resp.headers.get("retry-after")
                if retry_after and retry_after.isdigit():
                    wait = min(float(retry_after), 10.0)
                await asyncio.sleep(wait)
                continue
            break
        assert resp is not None
        if resp.status_code == 404:
            return None
        if resp.status_code == 429:
            raise PackagistError("Rate limited by Packagist. Wait a moment and retry with fewer packages.")
        if resp.status_code >= 400:
            raise PackagistError(f"Packagist returned HTTP {resp.status_code} for {url}. {resp.text[:200].strip()}".strip())
        try:
            return resp.json()
        except ValueError as exc:
            raise PackagistError(f"Packagist returned a non-JSON response for {url}.") from exc

    # Endpoint helpers -------------------------------------------------------------------------

    async def api(self, path: str, params: Any = None) -> Any:
        return await self.get(self.base_url + path, params)

    async def repo(self, path: str) -> Any:
        return await self.get(self.repo_url + path)
