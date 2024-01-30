from __future__ import annotations

import os
import pathlib
import subprocess

import py  # pyright: ignore [reportMissingTypeStubs]
import pytest

from docker_export import Image, Platform, export, get_export_filename


@pytest.fixture(scope="session")
def image_name() -> str:
    return "ghcr.io/offspot/base-httpd:1.0"


@pytest.fixture(scope="session")
def platform_name() -> str:
    return "arm64"


@pytest.fixture(scope="session")
def expected_filepath() -> pathlib.Path:
    return pathlib.Path("ghcr.io_offspot_base-httpd_1.0_linuxarm64.tar")


@pytest.fixture(scope="session")
def expected_filesize() -> int:
    return 5713920


@pytest.mark.slow
def test_export(
    tmpdir: py.path.local,
    image_name: str,
    platform_name: str,
    expected_filepath: pathlib.Path,
    expected_filesize: int,
):
    os.chdir(tmpdir)
    export(
        image=Image.parse(image_name),
        platform=Platform.parse(platform_name),
        to=pathlib.Path(
            get_export_filename(Image.parse(image_name), Platform.parse(platform_name))
        ),
    )
    assert expected_filepath.exists()
    assert expected_filepath.stat().st_size == expected_filesize


@pytest.mark.slow
def test_cli(
    tmpdir: py.path.local,
    image_name: str,
    platform_name: str,
    expected_filepath: pathlib.Path,
    expected_filesize: int,
):
    os.chdir(tmpdir)
    ps = subprocess.run(
        [
            "/usr/bin/env",
            "docker-export",
            "--platform",
            platform_name,
            image_name,
            ".",
        ],
        check=False,
    )
    assert ps.returncode == 0
    assert expected_filepath.exists()
    assert expected_filepath.stat().st_size == expected_filesize
