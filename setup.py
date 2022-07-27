#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim: ai ts=4 sts=4 et sw=4 nu

import pathlib
import subprocess
import sys

from setuptools import find_packages, setup

root_dir = pathlib.Path(__file__).parent


def read(*names, **kwargs):
    with open(root_dir.joinpath(*names), "r") as fh:
        return fh.read()


def get_version():
    return subprocess.run(
        [
            sys.executable,
            "-c",
            "from docker_export import __version__; print(__version__)",
        ],
        env={"PYTHONPATH": root_dir.joinpath("src")},
        text=True,
        capture_output=True,
    ).stdout.strip()


setup(
    name="docker_export",
    version=get_version(),
    description="Export docker image into tar file directly from registry API",
    long_description=read("README.md"),
    long_description_content_type="text/markdown",
    author="kiwix",
    author_email="reg@kiwix.org",
    url="https://github.com/offspot/docker_export",
    keywords="docker oci kiwix",
    license="GPLv3+",
    packages=find_packages("src"),
    package_dir={"": "src"},
    install_requires=[
        line.strip()
        for line in read("requirements.txt").splitlines()
        if not line.strip().startswith("#")
    ],
    extras_require={
        "all": ["humanfriendly>=8.0", "progressbar2>=4.0"],
    },
    setup_requires=["pytest-runner"],
    zip_safe=True,
    include_package_data=True,
    entry_points={
        "console_scripts": [
            "docker-export=docker_export:main",
        ]
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
    ],
    python_requires=">=3.9",
)
