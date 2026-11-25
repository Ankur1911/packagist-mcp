"""Composer version parsing and constraint matching (the common subset used in composer.json)."""

from __future__ import annotations

import re
from typing import Any

# Stability ranks: dev < alpha < beta < RC < stable < patch
_STAB = {"dev": 0, "alpha": 1, "a": 1, "beta": 2, "b": 2, "rc": 3, "stable": 4, "patch": 5, "pl": 5, "p": 5}
_VERSION_RE = re.compile(r"^v?(\d+(?:\.\d+){0,3})(?:[-_.]?(dev|alpha|a|beta|b|rc|patch|pl|p)[-_.]?(\d*))?(?:\+.*)?$", re.I)

VersionKey = tuple[tuple[int, int, int, int], int, int]


def parse_version(text: str) -> VersionKey | None:
    """Parse '1.2.3', 'v2.0', '3.0.0-RC1', '2.1.0.0-beta2'. Returns None for branches like 'dev-main' or '2.x-dev'."""
    m = _VERSION_RE.match(text.strip())
    if not m:
        return None
    nums = [int(x) for x in m.group(1).split(".")]
    nums += [0] * (4 - len(nums))
    stab = _STAB[m.group(2).lower()] if m.group(2) else 4
    n = int(m.group(3)) if m.group(3) else 0
    return (tuple(nums[:4]), stab, n)  # type: ignore[return-value]


def is_stable(text: str) -> bool:
    key = parse_version(text)
    return key is not None and key[1] >= 4


def _bound(text: str) -> VersionKey:
    key = parse_version(text)
    if key is None:
        raise ValueError(text)
    return key


def _floor(nums: tuple[int, int, int, int]) -> VersionKey:
    """Lowest possible version with these numbers (any pre-release counts)."""
    return (nums, 0, 0)


Comparator = tuple[str, VersionKey]


def _wildcard(m: re.Match) -> list[Comparator]:
    parts = [int(x) for x in m.group(1).split(".")]
    lo = parts + [0] * (4 - len(parts))
    hi = parts[:]
    hi[-1] += 1
    hi += [0] * (4 - len(hi))
    return [(">=", _floor(tuple(lo))), ("<", _floor(tuple(hi)))]  # type: ignore[arg-type]


def _nums(v: str) -> list[int]:
    return [int(x) for x in re.findall(r"\d+", v.split("-")[0])][:4]


def _pad(nums: list[int]) -> tuple[int, int, int, int]:
    return tuple((nums + [0] * 4)[:4])  # type: ignore[return-value]


def _caret(v: str) -> list[Comparator]:
    nums = _nums(v)
    idx = next((i for i, x in enumerate(nums) if x != 0), len(nums) - 1)
    hi = nums[:idx] + [nums[idx] + 1]
    return [(">=", _floor(_pad(nums))), ("<", _floor(_pad(hi)))]


def _tilde(v: str) -> list[Comparator]:
    nums = _nums(v)
    idx = max(len(nums) - 2, 0)
    hi = nums[:idx] + [nums[idx] + 1]
    return [(">=", _floor(_pad(nums))), ("<", _floor(_pad(hi)))]


def _parse_and(group: str) -> list[Comparator]:
    group = group.strip()
    if group in ("", "*", "x", "X"):
        return []
    # Hyphen range: "1.0 - 2.0" (upper bound inclusive; a partial upper bound allows the whole series)
    h = re.match(r"^v?(\d[\w.]*)\s+-\s+v?(\d[\w.]*)$", group)
    if h:
        lo = _bound(h.group(1))
        up_parts = h.group(2).split(".")
        if len(up_parts) < 3:
            up = [int(x) for x in up_parts]
            up[-1] += 1
            up += [0] * (4 - len(up))
            return [(">=", _floor(lo[0])), ("<", _floor(tuple(up)))]  # type: ignore[arg-type]
        return [(">=", _floor(lo[0])), ("<=", (_bound(h.group(2))[0], 9, 0))]
    comps: list[Comparator] = []
    glued = re.sub(r"(>=|<=|!=|==|<>|>|<|=|\^|~)\s+", r"\1", group)
    for tok in re.split(r"[\s,]+", glued):
        if not tok:
            continue
        tok = tok.split("@")[0] if "@" in tok and not tok.startswith("@") else tok
        if tok in ("*", "x", "X"):
            continue
        if tok.startswith("^"):
            comps += _caret(tok[1:].lstrip("v"))
        elif tok.startswith("~"):
            comps += _tilde(tok[1:].lstrip("v"))
        elif tok.startswith(("v", "V")) and tok[1:2].isdigit():
            tok = tok[1:]
            comps.extend(_parse_and(tok))
        else:
            w = re.match(r"^(\d+(?:\.\d+){0,2})\.[*xX]$", tok)
            if w:
                comps += _wildcard(w)
                continue
            m = re.match(r"^(>=|<=|!=|==|<>|>|<|=)?(.+)$", tok)
            assert m
            op = m.group(1) or "=="
            op = {"=": "==", "<>": "!="}.get(op, op)
            val = m.group(2)
            comps.append((op, _bound(val)))
    return comps


def parse_constraint(text: str) -> list[list[Comparator]] | None:
    """Parse a constraint into OR-groups of AND-comparators. None when it uses syntax we do not model
    (branches such as 'dev-main', 'x as y' aliases)."""
    if not isinstance(text, str):
        return None
    try:
        groups = [_parse_and(g) for g in re.split(r"\s*\|\|?\s*", text.strip())]
    except (ValueError, AssertionError, IndexError):
        return None
    return groups


def _holds(op: str, ver: VersionKey, bound: VersionKey) -> bool:
    if op == ">=":
        return ver >= bound
    if op == ">":
        return ver > bound
    if op == "<=":
        return ver <= bound
    if op == "<":
        return ver < bound
    if op == "!=":
        return ver != bound
    return ver == bound


def satisfies(version: str, constraint: str) -> bool | None:
    """True/False, or None when the version or constraint cannot be parsed."""
    key = parse_version(version)
    groups = parse_constraint(constraint)
    if key is None or groups is None:
        return None
    return any(all(_holds(op, key, b) for op, b in g) for g in groups)


def sort_key(version: str) -> VersionKey:
    return parse_version(version) or ((0, 0, 0, 0), 0, 0)


def expand_minified(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Expand Composer's minified metadata: each entry only carries fields that changed from the previous one;
    the string '__unset' removes a field."""
    out: list[dict[str, Any]] = []
    prev: dict[str, Any] = {}
    for e in entries:
        cur = dict(prev)
        for k, v in e.items():
            if v == "__unset":
                cur.pop(k, None)
            else:
                cur[k] = v
        out.append(cur)
        prev = cur
    return out
