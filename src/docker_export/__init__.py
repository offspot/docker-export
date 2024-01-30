#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import gzip
import hashlib
import http
import json
import logging
import os
import pathlib
import platform as py_platform
import re
import shutil
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from typing import Any

import requests
from pathvalidate import sanitize_filename

try:
    import progressbar  # pyright: ignore [reportMissingTypeStubs]
except ImportError:
    progressbar = None
try:
    import humanfriendly
except ImportError:
    humanfriendly = None

REQUEST_TIMEOUT = 60

__version__ = "1.1.0"
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("docker-export")
logging.getLogger("urllib3").setLevel(logging.WARNING)


class ImageNotFoundError(Exception): ...


class V2ImageNotFoundError(ImageNotFoundError):
    def __init__(
        self,
        image: Image,
        platform: Platform,
        platforms: list[Platform] | None = None,
    ):
        self.image = image
        self.platform = platform
        self.platforms = platforms or []

        super().__init__(
            f"Requested platform ({platform}) is not available "
            f"for image {image}. "
            f"Available platforms: {', '.join([str(p) for p in self.platforms])}",
        )


class V1ImageNotFoundError(ImageNotFoundError):
    def __init__(self, image: Image, platform: Platform):
        self.image = image
        self.platform = platform
        self.platforms = []

        super().__init__(
            f"Requested platform ({platform}) is not available "
            f"for v1 manifest (considered {platform.default()}) for image {image}"
        )


class LayersNotFoundError(Exception):
    def __init__(self, image: Image, platform: Platform):
        self.image = image
        self.platform = platform
        super().__init__(
            self,
            f"Layers missing for requested platform ({platform}) for image {image}.",
        )


def format_size(size: int) -> str:
    if humanfriendly:
        return humanfriendly.format_size(size, binary=True)
    return f"{size} bytes"


def format_json(data: Any) -> str:
    return json.dumps(data, indent=4)


class VisualProgressBar:
    def __init__(self, total: int | None = None):
        if progressbar is None:
            widgets = []
            self.bar = None
        else:
            widgets = [
                "[",
                progressbar.Timer(),
                "] ",
                progressbar.DataSize(),
                progressbar.Bar(),
                progressbar.AdaptiveTransferSpeed(),
                " (",
                progressbar.ETA(),
                ")",
            ]
            self.bar = progressbar.ProgressBar(max_value=total, widgets=widgets)
        self.seen_so_far = 0

    def callback(self, bytes_amount: int):
        self.seen_so_far += bytes_amount
        if self.bar is not None:
            self.bar.update(  # pyright: ignore [ reportUnknownMemberType]
                self.seen_so_far
            )
        else:
            print(f"\r{format_size(self.seen_so_far)} downloaded", end="")

    def finish(self):
        if self.bar is not None:
            self.bar.finish()
        else:
            print("")


@dataclass
class Platform:
    architecture: str
    os: str
    variant: str

    def __repr__(self):
        value = f"{self.os}/{self.architecture}"
        if self.variant:
            value += f"/{self.variant}"
        return value

    def __eq__(self, __value: object) -> bool:
        if not isinstance(__value, Platform):
            return False
        if self.os != __value.os or self.architecture != __value.architecture:
            return False
        default_variant: str = self.default_variant(self.architecture)
        return (self.variant or default_variant) == (__value.variant or default_variant)

    @classmethod
    def parse(cls, platform_str: str) -> Platform:
        if platform_str == "auto":
            return cls.auto()

        architecture = os = variant = ""
        parts = platform_str.split("/", 2)

        if len(parts) == 3:  # noqa: PLR2004
            os, architecture, variant = parts
        elif len(parts) == 2:  # noqa: PLR2004
            os, architecture = parts
        elif len(parts) == 1:
            architecture = parts[0]

        if not os:
            os = "linux"
        if not architecture:
            architecture = "amd64"
        if architecture == "arm32":
            architecture = "arm"
        if architecture == "i386":
            architecture = "386"

        if os not in ("linux", "windows"):
            raise ValueError(f"Invalid OS “{os}” from `{platform_str}`")

        if not variant and re.match(r"[\w\d]+v\d$", architecture):
            architecture, variant = re.split(r"(v\d)$", architecture, maxsplit=1)[:-1]

        if architecture not in (
            "amd64",
            "arm",
            "arm64",
            "386",
            "mips64le",
            "ppc64le",
            "riscv64",
            "s390x",
        ):
            raise ValueError(f"Invalid arch “{architecture}” from `{platform_str}`")

        return cls(architecture=architecture, os=os, variant=variant)

    @classmethod
    def default(cls) -> Platform:
        return cls.parse("linux/amd64")

    @classmethod
    def default_variant(cls, architecture: str):
        return {"arm64": "v8", "arm": "v7"}.get(architecture, "")

    @classmethod
    def auto(cls):
        machine = py_platform.machine()
        if machine.startswith("armv7"):
            return cls.parse("linux/arm/v7")
        elif machine.startswith("armv8"):
            return cls.parse("linux/arm64/v8")
        elif machine.startswith("arm"):
            return cls.parse("linux/arm/v6")
        elif re.match(r"^i(3|5|6)86", machine):
            return cls.parse("linux/i386")
        return cls.parse("linux/amd64")

    @classmethod
    def from_payload(cls, payload: dict[str, str]):
        return cls(
            architecture=payload.get("architecture", ""),
            os=payload.get("os", ""),
            variant=payload.get("variant", ""),
        )


@dataclass
class Image:
    registry: str
    repository: str
    name: str
    tag: str
    digest: str

    def __str__(self) -> str:
        value = f"{self.registry}/{self.repository}/{self.name}:{self.tag}"
        if self.digest:
            value += f"@{self.digest}"
        return value

    @property
    def fullname(self) -> str:
        return f"{self.repository}/{self.name}"

    @property
    def reg_fullname(self) -> str:
        return f"{self.registry}/{self.fullname}"

    @property
    def fs_name(self) -> str:
        return sanitize_filename(
            "_".join(pathlib.Path(self.reg_fullname).parts) + f"_{self.reference}"
        )

    @property
    def reference(self):
        return self.digest or self.tag

    @property
    def url(self) -> str:
        domain = (
            "hub.docker.com" if self.registry == "index.docker.io" else self.registry
        )
        prefix = "r/" if self.registry == "index.docker.io" else ""
        return f"https://{domain}/{prefix}/{self.fullname}"

    @classmethod
    def parse(
        cls,
        name: str,
        tag: str | None = None,
        digest: str | None = None,
        repository: str | None = None,
        registry: str | None = None,
    ):
        name_part = name.rsplit("/", 1)[-1]

        # do we have a digest?
        try:
            name_part, digest_part = name_part.split("@", 1)
        except ValueError:
            digest_part = None
        # do we have a tag?
        try:
            name_part, tag_part = name_part.split(":", 1)
        except ValueError:
            tag_part = None
        if not digest and digest_part:
            digest = digest_part
        if not tag and tag_part:
            tag = tag_part

        # default tag if none requested
        if not tag and not digest:
            tag = "latest"

        tree = name.rsplit(name_part, 1)[0].split("/")[:-1]
        if len(tree) == 1:
            repository = tree[0]
        elif len(tree) == 2:  # noqa: PLR2004
            registry, repository = tree
        elif len(tree) > 2:  # noqa: PLR2004
            raise ValueError(f"Unrecognized image tree: {tree}")

        if not repository or repository == "_":
            repository = "library"

        if not registry or registry == "docker.io":
            registry = "index.docker.io"

        name = name_part

        return cls(
            registry=registry,
            repository=repository,
            name=name,
            tag=tag or "",
            digest=digest or "",
        )

    def exists(self, platform: Platform) -> bool:
        return image_exists(image=self, platform=platform)

    def get_digest(self, platform: Platform) -> str:
        return get_image_digest(image=self, platform=platform)


@dataclass
class RegistryAuth:
    registry: str
    image: str
    token: str
    url: str
    service: str

    @classmethod
    def init(cls, image: Image) -> RegistryAuth:
        # default, fallback values
        url = f"https://{image.registry}/token"
        service = ""

        resp = requests.get(f"https://{image.registry}/v2/", timeout=REQUEST_TIMEOUT)
        if resp.status_code == http.HTTPStatus.UNAUTHORIZED:
            url = resp.headers["WWW-Authenticate"].split('"')[1]
            try:
                service = resp.headers["WWW-Authenticate"].split('"')[3]
            except IndexError:
                service = ""

        return cls(
            registry=image.registry,
            image=image.fullname,
            url=url,
            service=service,
            token="",
        )

    def authenticate(self):
        resp = requests.get(
            self.url,
            params={
                "service": self.service,
                "scope": f"repository:{self.image}:pull",
            },
            timeout=REQUEST_TIMEOUT,
        )

        self.token = resp.json().get("token")

    @property
    def headers(self) -> dict[str, str]:
        if not self.token:
            self.authenticate()
        return {"Authorization": f"Bearer {self.token}"}


def get_export_filename(image: Image, platform: Platform) -> str:
    """Filesystem-safe filename to export an image for a platform"""
    return sanitize_filename(f"{image.fs_name}_{platform}.tar")


def get_manifests(image: Image, auth: RegistryAuth):
    """get list of fat-manifests for the image"""
    resp = requests.get(
        f"https://{image.registry}/v2/{image.repository}/{image.name}"
        f"/manifests/{image.reference}",
        headers=dict(
            **auth.headers,
            **{"Accept": "application/vnd.docker.distribution.manifest.list.v2+json"},
        ),
        timeout=REQUEST_TIMEOUT,
    )
    if resp.status_code == http.HTTPStatus.UNAUTHORIZED:
        raise OSError(
            f"HTTP {resp.status_code}: {resp.reason} -- "
            "This **may** indicate an incorrect image name/registry/repo/tag.\n"
            f"Check {image.url}"
        )
    if resp.status_code == http.HTTPStatus.NOT_FOUND:
        raise ValueError(
            f"HTTP {resp.status_code}: {resp.reason} -- "
            f"Image name is probably incorrect.\nCheck {image.url}"
        )
    if resp.status_code != http.HTTPStatus.OK:
        raise OSError(f"HTTP {resp.status_code}: {resp.reason} -- {resp.text}")

    return resp.json()


def get_layers_manifest_for(
    image: Image, auth: RegistryAuth, reference: str | None = None
):
    """get list of layers for the image using a specific reference"""
    reference = reference or image.reference
    resp = requests.get(
        f"https://{image.registry}/v2/{image.repository}/{image.name}"
        f"/manifests/{reference}",
        headers=dict(
            **auth.headers,
            **{"Accept": "application/vnd.docker.distribution.manifest.v2+json"},
        ),
        timeout=REQUEST_TIMEOUT,
    )
    if resp.status_code != http.HTTPStatus.OK:
        raise OSError("HTTP {resp.status_code}: {resp.reason} -- {resp.text}")

    return resp.json()


def get_layers_from_v1_manifest(
    image: Image, platform: Platform, manifest: dict[str, Any]
) -> dict[str, Any]:
    architecture = manifest.get("architecture", "amd64")
    os = manifest.get("os", "linux")

    if platform != Platform(architecture=architecture, os=os, variant=""):
        raise ValueError(
            f"Requested platform ({platform}) is not available "
            f"for single-platform image {image}"
        )

    return {
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "schemaVersion": 2,
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "digest": json.loads(manifest["history"][0]["v1Compatibility"])["id"],
            # "size": 1,
        },
        "layers": [
            {
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "digest": layer["blobSum"],
                # "size": None,
                "platform": {"architecture": architecture, "os": os},
            }
            for layer in manifest["fsLayers"]
        ],
    }


def get_layers_manifest(image: Image, platform: Platform, auth: RegistryAuth):
    """get layers manifest for platform"""

    manifest = None
    fat_manifests = get_manifests(image, auth)
    logger.debug(f"fat_manifests={format_json(fat_manifests)}")

    if fat_manifests["schemaVersion"] == 1:
        return get_layers_from_v1_manifest(
            image=image, platform=platform, manifest=fat_manifests
        )

    # image is single-platform, thus considered linux/amd64
    if "layers" in fat_manifests:
        if platform != platform.default():
            raise V1ImageNotFoundError(image, platform)
        manifest = fat_manifests
    else:
        # multi-platform image
        platforms: list[Platform] = []
        for arch_manifest in fat_manifests.get("manifests", []):
            if not arch_manifest.get("platform"):
                continue
            manifest_platform = Platform.from_payload(arch_manifest["platform"])
            if platform == manifest_platform:
                manifest = get_layers_manifest_for(image, auth, arch_manifest["digest"])
            platforms.append(manifest_platform)

        if not manifest:
            raise V2ImageNotFoundError(image, platform, platforms)

    logger.debug(f"layers_manifest={format_json(manifest)}")
    if not manifest.get("layers"):
        raise LayersNotFoundError(image, platform)
    return manifest


def make_layer_id(parent_id: str, layer: dict[str, Any]) -> str:
    """Fake layer ID. Don't know how Docker generates it"""
    return hashlib.sha256(
        (parent_id + "\n" + layer["digest"] + "\n").encode("utf-8")
    ).hexdigest()


def get_layer_dir(image_dir: pathlib.Path, layer_id: str) -> pathlib.Path:
    layer_dir = image_dir / layer_id
    layer_dir.mkdir(parents=True, exist_ok=True)
    return layer_dir


def download_layer_blob(
    image: Image,
    parent_id: str,
    layer: dict[str, Any],
    layer_dir: pathlib.Path,
    auth: RegistryAuth,
):
    layer_digest = layer["digest"]

    # Creating layer.tar file
    size_str = f" {format_size(layer['size'])}" if layer.get("size") else ""
    logger.info(f"> [{layer_digest[7:19]}] Downloading{size_str}…")

    resp = requests.get(
        f"https://{image.registry}/v2/{image.fullname}/blobs/{layer_digest}",
        headers=dict(
            **auth.headers,
            **{"Accept": "application/vnd.docker.distribution.manifest.v2+json"},
        ),
        stream=True,
        timeout=REQUEST_TIMEOUT,
    )
    if (
        resp.status_code != http.HTTPStatus.OK
    ):  # When the layer is located at a custom URL
        resp = requests.get(
            layer["urls"][0],
            headers=dict(
                **auth.headers,
                **{"Accept": "application/vnd.docker.distribution.manifest.v2+json"},
            ),
            stream=True,
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code != http.HTTPStatus.OK:
            raise OSError(
                f"ERROR: Cannot download layer {layer_digest[7:19]} "
                f"[HTTP {resp.status_code}] {resp.headers['Content-Length']}"
            )
    resp.raise_for_status()

    total_exp = int(resp.headers["Content-Length"])
    chunk_size = 1048576
    received = 0
    progress = VisualProgressBar(total_exp)

    with open(layer_dir / "layer_gzip.tar", "wb") as fh:
        for chunk in resp.iter_content(chunk_size=chunk_size):
            if chunk:
                fh.write(chunk)
                received += len(chunk)
                progress.callback(len(chunk))
        progress.finish()

    return parent_id


def extract_layer(layer_digest: str, layer_dir: pathlib.Path):
    logger.info(f"> [{layer_digest[7:19]}] Extracting...")  # Ugly but works everywhere
    layer_ark = layer_dir / "layer.tar"
    with open(layer_dir / "layer.tar", "wb") as fh:  # Decompress gzip response
        with gzip.open(layer_dir / "layer_gzip.tar", "rb") as gzfh:
            shutil.copyfileobj(gzfh, fh)
    layer_dir.joinpath("layer_gzip.tar").unlink()

    return layer_ark


def write_layer_metadata(
    layer_dir: pathlib.Path,
    layer_id: str,
    parent_id: str,
    layer: dict[str, Any],
    manifest: dict[str, Any],
):
    logger.info(f"> [{layer['digest'][7:19]}] Adding metadata…")

    with open(layer_dir / "VERSION", "w") as fh:
        fh.write("1.0")

    with open(layer_dir / "json", "w") as fh:
        # last layer = config manifest minus history and rootfs
        if manifest["layers"][-1]["digest"] == layer["digest"]:
            # NOTE: reusing loaded manifest with decoded JSON values.
            # Docker doesn't seem to decode JSON here
            layer_manifest = copy.copy(manifest)
            for key in (
                "history",
                "rootfs",
                "rootfS",
            ):  # Microsoft loves case insensitiveness
                if key in layer_manifest:
                    del layer_manifest[key]
        else:  # other layers json are empty
            layer_manifest = {
                "created": "1970-01-01T00:00:00Z",
                "container_config": {
                    "Hostname": "",
                    "Domainname": "",
                    "User": "",
                    "AttachStdin": False,
                    "AttachStdout": False,
                    "AttachStderr": False,
                    "Tty": False,
                    "OpenStdin": False,
                    "StdinOnce": False,
                    "Env": None,
                    "Cmd": None,
                    "Image": "",
                    "Volumes": None,
                    "WorkingDir": "",
                    "Entrypoint": None,
                    "OnBuild": None,
                    "Labels": None,
                },
            }
        layer_manifest["id"] = layer_id
        if parent_id:
            layer_manifest["parent"] = parent_id
        parent_id = layer_manifest["id"]
        fh.write(format_json(layer_manifest))
        return parent_id


def bundle_image(
    image: Image,
    image_dir: pathlib.Path,
    target: pathlib.Path,
    manifest: list[dict[str, Any]],
    config: bytes,
    latest_layer_id: str,
):
    logger.info("Adding Image metadata…")
    # image digest
    with open(image_dir / manifest[0]["Config"], "wb") as fh:
        fh.write(config)

    with open(image_dir / "manifest.json", "w") as fh:
        fh.write(format_json(manifest))

    with open(image_dir / "repositories", "w") as fh:
        fh.write(
            format_json(
                {f"{image.registry}/{image.fullname}": {image.tag: latest_layer_id}}
            )
        )

    # Create image tar and clean tmp folder
    logger.info(f"Creating archive at {target}")
    with tarfile.open(target, "w") as tar:
        tar.add(image_dir, arcname=os.path.sep)

    logger.info(f"Removing temp image dir {image_dir}")
    shutil.rmtree(
        image_dir,
        onerror=lambda function, path, excinfo: logger.warning(
            f"Error Removing temp image dir ({image_dir})"
            f": {function} failed for {path} with {excinfo}"
        ),
    )


def export_layers(
    image: Image,
    image_dir: pathlib.Path,
    target: pathlib.Path,
    auth: RegistryAuth,
    manifest: dict[str, Any],
):
    """create image from layers manifest"""
    total_size = sum([layer.get("size", 0) for layer in manifest["layers"]])
    size_str = f" ({format_size(total_size)})" if total_size else ""
    logger.info(
        f"Exporting {len(manifest['layers'])} layers{size_str} into {image_dir}"
    )

    # write image digest
    digest = manifest["config"]["digest"]
    logger.debug(f"{digest=}")
    resp = requests.get(
        f"https://{image.registry}/v2/{image.fullname}/blobs/{digest}",
        headers=auth.headers,
        timeout=REQUEST_TIMEOUT,
    )
    if resp.status_code == http.HTTPStatus.NOT_FOUND:
        logger.error(
            "Unsupported manifest schema/version: digest blob not found\n\n"
            "###############\n"
            "Use regctl instead https://github.com/regclient/regclient\n"
            f"regctl image export {image} {target}\n"
            "###############\n"
        )
    resp.raise_for_status()
    config = resp.content

    new_manifest: list[dict[str, Any]] = [
        {
            "Config": f"{digest[7:]}.json",
            "RepoTags": [f"{image.reg_fullname}:{image.tag}"],
            "Layers": [],
        }
    ]

    parent_id = ""
    layer_id = "unknown"
    for layer in manifest["layers"]:
        layer_id = make_layer_id(parent_id=parent_id, layer=layer)
        layer_dir = get_layer_dir(image_dir=image_dir, layer_id=layer_id)
        download_layer_blob(
            image=image,
            parent_id=parent_id,
            layer=layer,
            layer_dir=layer_dir,
            auth=auth,
        )
        layer_ark = extract_layer(layer_dir=layer_dir, layer_digest=layer["digest"])
        new_manifest[0]["Layers"].append(str(layer_ark.relative_to(image_dir)))
        parent_id = write_layer_metadata(
            layer_dir=layer_dir,
            layer_id=layer_id,
            parent_id=parent_id,
            layer=layer,
            manifest=manifest,
        )
    bundle_image(
        image=image,
        image_dir=image_dir,
        target=target,
        config=config,
        manifest=new_manifest,
        latest_layer_id=layer_id,
    )
    logger.info(f"Docker image exported: {target}")


def image_exists(image: Image, platform: Platform) -> bool:
    """whether image exists on the registry"""
    auth = RegistryAuth.init(image)
    auth.authenticate()
    try:
        get_layers_manifest(image=image, platform=platform, auth=auth)
    except Exception as exc:
        logger.exception(exc)
        return False
    return True


def get_image_digest(image: Image, platform: Platform) -> str:
    """Current digest for an Image

    Value of the current in-registry image for our platform.

    For v1 manifests and single-arch images, this is not the same value
    as in the registry's UI.
    Not much of a problem for us as images to be used here should be v2/multi
    and what's return is consistent and will be used only for comparison
    to check if a tag has been updated or not"""

    auth = RegistryAuth.init(image)
    auth.authenticate()
    fat_manifests = get_manifests(image, auth)

    if fat_manifests["schemaVersion"] == 1:
        return get_layers_from_v1_manifest(
            image=image, platform=platform, manifest=fat_manifests
        )["config"]["digest"]

    # image is single-platform, thus considered linux/amd64
    if "layers" in fat_manifests:
        if platform != platform.default():
            raise V1ImageNotFoundError(image=image, platform=platform)
        return fat_manifests["config"]["digest"]
    # multi-platform image
    platforms: list[Platform] = []
    for arch_manifest in fat_manifests.get("manifests", []):
        if not arch_manifest.get("platform"):
            continue
        manifest_platform = Platform.from_payload(arch_manifest["platform"])
        if platform == manifest_platform:
            return arch_manifest["digest"]
        platforms.append(manifest_platform)

    raise V2ImageNotFoundError(image=image, platform=platform, platforms=platforms)


def export(
    image: Image,
    platform: Platform,
    to: pathlib.Path,
    build_dir: pathlib.Path | None = None,
):
    """export image into `to` tar archive

    Params:
        `to`: a .tar destination to write image to
        `build_dir`: a folder to (create a temp dir in to) write intermediate layers
         into while fetching."""

    logger.info(f"Starting {image} ({platform}) export into {to}")
    # make sure destination and build-dir exists
    to.parent.mkdir(parents=True, exist_ok=True)
    if build_dir:
        build_dir.mkdir(parents=True, exist_ok=True)

    auth = RegistryAuth.init(image)
    auth.authenticate()
    manifest = get_layers_manifest(image=image, platform=platform, auth=auth)

    with tempfile.TemporaryDirectory(
        suffix=".tmp", prefix=to.stem, dir=build_dir
    ) as image_dir:
        export_layers(
            image=image,
            image_dir=pathlib.Path(image_dir),
            target=to,
            auth=auth,
            manifest=manifest,
        )

    return to


def main():
    parser = argparse.ArgumentParser(
        prog="docker-export",
        description="Docker Registry HTTP API V2 based Image extractor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
    docker-export --platform linux/arm64 kiwix/kiwix-tools:3.3.0 kiwix-tools.tar
    docker-export alpine alpine.tar

See https://docs.docker.com/desktop/multi-arch/ for platforms list""",
    )

    parser.add_argument("-V", "--version", action="version", version=__version__)

    parser.add_argument(
        help="name of image to pull. Can optionnaly include registry, repository "
        "and tag or digest using this format: "
        "[registry/][repository/]image[:tag|@digest]",
        dest="name",
    )

    parser.add_argument(
        help="path to write exported image to. If it doesn't end in .tar, "
        "it is expected to be a folder to write the image into",
        dest="output",
    )

    parser.add_argument(
        "--registry",
        help="registry to pull image from. "
        "Defaults to registry definition in {image} or `docker.io`",
        dest="registry",
    )

    parser.add_argument(
        "--repository",
        help="repository to pull image from. "
        "Defaults to repository definition in {image} or `library`",
        dest="repository",
    )

    parser.add_argument(
        "--tag",
        help="tag version of image to pull. "
        "Defaults to tag definition in {image} or `latest`",
        dest="tag",
    )

    parser.add_argument(
        "--digest", help="digest version of image to pull", dest="digest"
    )

    parser.add_argument(
        "--platform",
        help="Platform to download image for. "
        f"Defaults to `{Platform.auto()}` (guessed). "
        "Ex: linux/amd64, linux/arm/v6, linux/arm/v7, linux/arm64, windows/amd64",
        default="auto",
        dest="platform",
    )

    parser.add_argument(
        "--debug",
        help="Enable debug output",
        action="store_true",
        dest="debug",
    )

    args = dict(parser.parse_args()._get_kwargs())
    debug = args.pop("debug", False)
    output = args.pop("output", "")
    build_dir = args.pop("output", "")
    platform = args.pop("platform", "auto")
    if debug:
        logger.setLevel(logging.DEBUG)

    try:
        platform = Platform.parse(platform)
        image = Image.parse(**args)
        dest = pathlib.Path(output).expanduser().resolve()
        if not dest.suffix == ".tar":
            dest = dest.joinpath(get_export_filename(image=image, platform=platform))
        build_dir = (
            pathlib.Path(build_dir).expanduser().resolve() if build_dir else None
        )
        export(image=image, platform=platform, to=dest, build_dir=build_dir)
        sys.exit(0)
    except Exception as exc:
        logger.error(str(exc))
        if debug:
            logger.exception(exc)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
