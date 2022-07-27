# docker-export

[![PyPI version shields.io](https://img.shields.io/pypi/v/docker_export)](https://pypi.org/project/docker_export/)
[![CodeFactor](https://www.codefactor.io/repository/github/offspot/docker-export/badge)](https://www.codefactor.io/repository/github/offspot/docker-export)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Export Docker Images to a single `.tar` without `docker`: Using Python
and the registry's API.

## Installation

`docker-export` is a Python3 software. You are advised to use it in a
virtual environment to avoid installing software dependencies on your
system.

### Locally (with virtualenv)

```bash
python3 -m venv env              # Create virtualenv
source env/bin/activate          # Activate the virtualenv
pip3 install docker_export[all]  # Install dependencies
docker-export --help             # Display docker-export help
```

Call `deactivate` to quit the virtual environment.

### Globally (as root)

```bash
sudo -H pip3 install docker_export[all]
```

## Usages

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
