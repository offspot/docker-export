from __future__ import annotations

import pytest

from docker_export import Image, Platform

kiwix_tools: str = "ghcr.io/kiwix/kiwix-tools"


@pytest.mark.slow
@pytest.mark.parametrize(
    "image_name, platform_name, should_exist",
    [
        (f"{kiwix_tools}:3.5.0", "linux/amd64", True),
        (f"{kiwix_tools}:3.5.0", "linux/arm64", True),
        (f"{kiwix_tools}:3.5.0", "linux/armv7", True),
        (f"{kiwix_tools}:3.5.0", "linux/armv6", False),
        (f"{kiwix_tools}:3.5.0", "linux/386", False),
        (f"{kiwix_tools}:3.5.0-2", "linux/amd64", True),
        (f"{kiwix_tools}:3.5.0-2", "linux/arm64", True),
        (f"{kiwix_tools}:3.5.0-2", "linux/armv7", True),
        (f"{kiwix_tools}:3.5.0-2", "linux/armv6", True),
        (f"{kiwix_tools}:3.5.0-2", "linux/386", True),
    ],
)
def test_exist(*, image_name: str, platform_name: str, should_exist: bool):
    assert Image.parse(image_name).exists(Platform.parse(platform_name)) is should_exist
