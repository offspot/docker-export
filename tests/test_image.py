from __future__ import annotations

import pytest

from docker_export import Image


@pytest.mark.parametrize(
    "value, exp_str, exp_registry, exp_repository, exp_name, exp_tag, exp_digest",
    [
        (
            "kiwix/kiwix-serve",
            "index.docker.io/kiwix/kiwix-serve:latest",
            "index.docker.io",
            "kiwix",
            "kiwix-serve",
            "latest",
            "",
        ),
        (
            "matomo",
            "index.docker.io/library/matomo:latest",
            "index.docker.io",
            "library",
            "matomo",
            "latest",
            "",
        ),
        (
            "ghcr.io/kiwix/kiwix-tools"
            "@sha256:88bdb5d12b5599efb818162d2eb610a957d0078952ca5a6edc7d3aa9a307f1aa",
            "ghcr.io/kiwix/kiwix-tools:"
            "@sha256:88bdb5d12b5599efb818162d2eb610a957d0078952ca5a6edc7d3aa9a307f1aa",
            "ghcr.io",
            "kiwix",
            "kiwix-tools",
            "",
            "sha256:88bdb5d12b5599efb818162d2eb610a957d0078952ca5a6edc7d3aa9a307f1aa",
        ),
    ],
)
def test_parse(
    *,
    value: str,
    exp_str: str,
    exp_registry: str,
    exp_repository: str,
    exp_name: str,
    exp_tag: str,
    exp_digest: str,
):
    image = Image.parse(value)
    assert str(image) == exp_str
    assert image.registry == exp_registry
    assert image.repository == exp_repository
    assert image.name == exp_name
    assert image.tag == exp_tag
    assert image.digest == exp_digest
