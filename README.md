# docker-export

[![CodeFactor](https://www.codefactor.io/repository/github/offspot/docker-export/badge)](https://www.codefactor.io/repository/github/offspot/docker-export)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![codecov](https://codecov.io/gh/offspot/docker-export/branch/main/graph/badge.svg)](https://codecov.io/gh/offspot/docker-export)
[![PyPI version shields.io](https://img.shields.io/pypi/v/docker-export.svg)](https://pypi.org/project/docker-export/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/docker-export.svg)](https://pypi.org/project/docker-export)

Export Docker Images (**v2 manifests only**) to a single `.tar`, without `docker`;
Using Python and the registry's API.

## Usages

### Installation

`docker-export` is a Python3 software. You are advised to use it in a
virtual environment to avoid installing software dependencies on your
system.


```bash
python3 -m venv ./env  # creates a virtual python environment in ./env folder
./env/bin/pip install -U pip  # upgrade pip (package manager). recommended
./env/bin/pip install -U docker-export[all]  # install/upgrade docker-export inside virtualenv

# direct access to in-virtualenv docker-export binary, without shell-attachment
./env/bin/docker-export --help
# alias or link it for convenience
sudo ln -s $(pwd)/env/bin/docker-export /usr/local/bin/

# alternatively, attach virtualenv to shell
source env/bin/activate
docker-export --help
deactivate  # unloads virtualenv from shell
```


### Command line

```sh
docker-export --platform linux/arm/v7 ghcr.io/kiwix/kiwix-tools:3.0.0 kiwix-tools.tar
```

### Python module

```py
import pathlib

from docker_export import Platform, Image, export

export(
    image=Image.parse("kiwix/kiwix-tools:3.3.0"),
    platform=Platform.auto(),
    to=pathlib.Path("kiwix-tools.tar"),
)
```

### Using exported image

Exported images (tarball) are loaded into dockerd via:

```sh
docker load -i IMAGE.tar

# verify it's been properly added
docker images
```
