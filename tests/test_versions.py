import pytest

from packagist_mcp.versions import expand_minified, is_stable, parse_constraint, parse_version, satisfies, sort_key


@pytest.mark.parametrize(
    "version,constraint,expected",
    [
        ("2.9.1", "^2.0", True),
        ("3.0.0", "^2.0", False),
        ("0.3.5", "^0.3", True),
        ("0.4.0", "^0.3", False),
        ("0.0.3", "^0.0.3", True),
        ("0.0.4", "^0.0.3", False),
        ("1.2.9", "~1.2.3", True),
        ("1.3.0", "~1.2.3", False),
        ("1.9", "~1.2", True),
        ("2.0.0", "~1.2", False),
        ("1.5.0", "1.*", True),
        ("2.0.0", "1.*", False),
        ("1.5.0", ">=1.0,<2.0", True),
        ("1.5.0", ">=1.0 <2.0", True),
        ("1.5.0", ">=2.0 || <1.6", True),
        ("2.0.5", "1.0 - 2.0", True),
        ("3.0.0", "1.0 - 2.0", False),
        ("2.5.0", "^1.0 || ^2.0", True),
        ("7.4.0", "^7.4|^8.0", True),
        ("1.2.0", ">= 1.2", True),
        ("1.0.0-RC1", "<1.0.0", True),
        ("1.1.0", "!=1.1.0", False),
        ("1.2.3", "1.2.3", True),
        ("1.2.4", "1.2.3", False),
        ("v3.9.3", "^3.0", True),
        ("5.0.0", "*", True),
    ],
)
def test_satisfies(version, constraint, expected):
    assert satisfies(version, constraint) is expected


def test_unparseable_constraint_and_version():
    assert parse_constraint("dev-main") is None
    assert satisfies("1.0.0", "dev-main") is None
    assert satisfies("2.x-dev", "^2.0") is None
    assert satisfies("1.0.0", "^1.0 as 2.0") is None


def test_stability_and_ordering():
    assert is_stable("3.13.0") and is_stable("v2.0") and not is_stable("3.0.0-RC1") and not is_stable("dev-main")
    order = sorted(["1.0.0", "1.0.0-RC1", "1.0.0-beta2", "1.0.0-alpha1", "0.9.9", "1.0.1"], key=sort_key)
    assert order == ["0.9.9", "1.0.0-alpha1", "1.0.0-beta2", "1.0.0-RC1", "1.0.0", "1.0.1"]
    assert parse_version("2.1.0.0")[0] == (2, 1, 0, 0)


def test_expand_minified():
    entries = [
        {"version": "2.0.0", "require": {"php": ">=8"}, "abandoned": True},
        {"version": "1.9.0"},
        {"version": "1.8.0", "require": {"php": ">=7"}, "abandoned": "__unset"},
    ]
    out = expand_minified(entries)
    assert out[1]["require"] == {"php": ">=8"} and out[1]["abandoned"] is True
    assert out[2]["require"] == {"php": ">=7"} and "abandoned" not in out[2]
