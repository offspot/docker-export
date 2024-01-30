from __future__ import annotations

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


def test_from_payload(): ...


@pytest.mark.parametrize(
    "value_a, value_b, should_match",
    [
        ("linux/amd64", "linux/amd64", True),
        ("linux/amd64", "linux/amd64/v3", False),
        ("linux/armv6", "linux/arm", False),
        ("linux/armv7", "linux/arm", True),
        ("linux/armv6", "linux/arm/v6", True),
        ("linux/armv6", "linux/arm/v7", False),
        ("linux/armv6", "linux/arm/v8", False),
        ("linux/armv7", "linux/arm/v7", True),
        ("linux/arm64/v8", "linux/arm64/v8", True),
        ("linux/arm64", "linux/arm64/v8", True),
    ],
)
def test_match(*, value_a: str, value_b: str, should_match: bool):
    assert (Platform.parse(value_a) == Platform.parse(value_b)) is should_match
