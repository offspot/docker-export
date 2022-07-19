docker-export
=============

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
