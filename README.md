# docker-export

[![PyPI version shields.io](https://img.shields.io/pypi/v/docker_export)](https://pypi.org/project/docker_export/)
[![CodeFactor](https://www.codefactor.io/repository/github/offspot/docker-export/badge)](https://www.codefactor.io/repository/github/offspot/docker-export)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Export Docker Images to a single `.tar` without `docker`: Using Python and the registry's API.

## Usages


```sh
pip3 install docker_export[all]
```

### cli script

```sh
docker-export --platform linux/arm/v7 ghcr.io/kiwix/kiwix-tools:3.0.0 kiwix-tools.tar
```

### python module

```py
import pathlib

from docker_export import Platform, Image, export

export(
    image=Image.parse("kiwix/kiwix-tools:3.3.0"),
    platform=Platform.auto(),
    to=pathlib.Path("kiwix-tools.tar"),
)
```
