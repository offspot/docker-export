from __future__ import annotations

from typing import Any

import pytest

from docker_export import Platform


def test_default():
    assert Platform.default().os == "linux"
    assert Platform.default().architecture == "amd64"
    assert Platform.default().variant == ""
    assert Platform.default() == Platform.parse("linux/amd64")


def test_default_variant():
    assert Platform.default_variant("arm64") == "v8"
    assert Platform.default_variant("arm") == "v7"


@pytest.mark.parametrize(
    "value, exp_str, exp_os, exp_arch, exp_variant",
    [
        ("linux/amd64", "linux/amd64", "linux", "amd64", ""),
        ("linux/arm64/v8", "linux/arm64/v8", "linux", "arm64", "v8"),
        ("linux/arm64", "linux/arm64", "linux", "arm64", ""),
    ],
)
def test_parse(
    *, value: str, exp_str: str, exp_os: str, exp_arch: str, exp_variant: str
):
    platform = Platform.parse(value)
    assert str(platform) == exp_str
    assert platform.os == exp_os
    assert platform.architecture == exp_arch
    assert platform.variant == exp_variant


@pytest.mark.parametrize(
    "value",
    [
        "linux",
        "linux/amdd64",
    ],
)
def test_parse_error(value: str):
    with pytest.raises(ValueError):
        Platform.parse(value)


def test_from_payload():
    ...


@pytest.mark.parametrize(
    "value_a, payload, should_match",
    [
        ("linux/amd64", {"architecture": "linux", "os": "amd64"}, False),
        ("linux/amd64", {"architecture": "amd64", "os": "linux"}, True),
        (
            "linux/amd64",
            {"architecture": "amd64", "os": "linux", "variant": "v3"},
            True,
        ),
        ("linux/armv6", {"architecture": "arm", "os": "linux", "variant": "v6"}, True),
        ("linux/armv6", {"architecture": "arm", "os": "linux"}, False),
        ("linux/armv6", {"architecture": "arm", "os": "linux", "variant": "v7"}, False),
        ("linux/armv6", {"architecture": "arm", "os": "linux", "variant": "v8"}, False),
        ("linux/armv7", {"architecture": "arm", "os": "linux"}, True),
        ("linux/armv7", {"architecture": "arm", "os": "linux", "variant": "v7"}, True),
        (
            "linux/arm64/v8",
            {"architecture": "arm64", "os": "linux", "variant": "v8"},
            True,
        ),
        (
            "linux/arm64",
            {"architecture": "arm64", "os": "linux", "variant": "v8"},
            True,
        ),
    ],
)
def test_match(*, value_a: str, payload: dict[str, Any], should_match: bool):
    assert Platform.parse(value_a).match(payload) is should_match
