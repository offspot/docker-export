from __future__ import annotations

import pytest

from docker_export import Image, Platform

kiwix_tools: str = "ghcr.io/kiwix/kiwix-tools"


@pytest.mark.slow
@pytest.mark.parametrize(
    "image_name, platform_name, expected_digest",
    [
        (
            "matomo:4.4.0-fpm-alpine",
            "linux/s390x",
            "sha256:d232f018fafe0686acfabae51ddc40a315c557bcd2401ee36e54b2b018d049de",
        ),
        (
            "helloysd/caddy:0.10.11",
            "linux/amd64",
            "672342e30b241ae37f442b0afdd6e744f776af3bd602c4bceaa8dcf2547841bd",
            # different from hub (v1 manifest)
            # "sha256:8a7b91584f5d0ee6211249d05ec51f026b763d3e1a87885e7d0d6968c42ad6b1",
        ),
        (
            f"{kiwix_tools}:3.5.0-2",
            "linux/amd64",
            "sha256:a608b4e759efa9e4bba8818dff61729bb1ad988457b4a8e4f7d356fece8bc9a1",
        ),
        (
            f"{kiwix_tools}:3.5.0-2",
            "linux/arm64",
            "sha256:f7d859179210c4407447e4e37e401cefc831dfe3e686b66988a225417db884c8",
        ),
        (
            f"{kiwix_tools}:3.5.0-2",
            "linux/arm64/v8",
            "sha256:f7d859179210c4407447e4e37e401cefc831dfe3e686b66988a225417db884c8",
        ),
        (
            f"{kiwix_tools}:3.5.0-2",
            "linux/armv7",
            "sha256:8251a47204d613ae3635815d0dc80fb9a5cf4c4cb55d4142d7bad666783a19ba",
        ),
        (
            f"{kiwix_tools}:3.5.0-2",
            "linux/armv6",
            "sha256:a0b4788df863875833f5bc8919fe250e3b76b9c140b6a0f06740401530e2d285",
        ),
        (
            f"{kiwix_tools}:3.5.0-2",
            "linux/386",
            "sha256:177065d8b8e3f928b5b1afda8139fed0f70b1f4a0f5b0b2f2ab3e17a238faab3",
        ),
    ],
)
def test_get_digest(*, image_name: str, platform_name: str, expected_digest: str):
    assert (
        Image.parse(image_name).get_digest(Platform.parse(platform_name))
        == expected_digest
    )
