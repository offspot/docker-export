#!/usr/bin/env python3

import argparse
import copy
import gzip
import hashlib
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
from typing import Dict, Optional

import requests

try:
    import progressbar
except ImportError:
    progressbar = None
try:
    import humanfriendly
except ImportError:
    humanfriendly = None

__version__ = "0.4"
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("docker-export")
logging.getLogger("urllib3").setLevel(logging.WARNING)


class ImageNotFound(Exception):
    ...


class V2ImageNotFound(ImageNotFound):
    def __init__(self, image, platform, platforms=None):
        self.image = image
        self.platform = platform
        self.platforms = platforms or []

        super().__init__(
            f"Requested platform ({platform}) is not available "
            f"for image {image}. "
            f"Available platforms: {', '.join([str(p) for p in self.platforms])}",
        )


class V1ImageNotFound(ImageNotFound):
    def __init__(self, image, platform):
        self.image = image
        self.platform = platform
        self.platforms = []

        super().__init__(
            f"Requested platform ({platform}) is not available "
            f"for v1 manifest (considered {platform.default()}) for image {image}"
        )


class LayersNotFound(Exception):
    def __init__(self, image, platform):
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


def format_json(data: Dict) -> str:
    return json.dumps(data, indent=4)


class VisualProgressBar:
    def __init__(self, total: int = None):
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
        self.bar.update(self.seen_so_far)

    def finish(self):
        self.bar.finish()


class NoProgressBar:
    def __init__(self, *args, **kwargs):
        self.seen_so_far = 0

    def callback(self, bytes_amount: int):
        self.seen_so_far += bytes_amount
        print(f"\r{format_size(self.seen_so_far)} downloaded", end="")

    def finish(self):
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

    @classmethod
    def parse(cls, platform_str: str, **kwargs):
        if platform_str == "auto":
            return cls.auto()

        architecture = os = variant = ""
        parts = platform_str.split("/", 2)

        match len(parts):
            case 3:
                os, architecture, variant = parts
            case 2:
                os, architecture = parts
            case 1:
                architecture = parts[0]

        if not os:
            os = "linux"
        if not architecture:
            architecture = "amd64"
        if architecture == "arm32":
            architecture = "arm"

        if os not in ("linux", "windows"):
            raise ValueError(f"Invalid OS “{os}” from `{platform_str}`")

        if not variant and re.match(r"[\w\d]+v\d$", architecture):
            architecture, variant = re.split(r"(v\d)$", architecture, 1)[:-1]

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

        if architecture == "arm" and not variant:
            raise ValueError(
                f"Missing variant for arch “{architecture}” from `{platform_str}`"
            )

        return cls(architecture=architecture, os=os, variant=variant)

    @classmethod
    def default(cls):
        return cls.parse("linux/amd64")

    @classmethod
    def default_variant(cls, architecture):
        return {"arm64": "v8", "arm32": "v7"}.get(architecture, "")

    @classmethod
    def auto(cls):
        machine = py_platform.machine()
        if machine.startswith("armv7"):
            return cls.parse("linux/arm/v7")
        elif machine.startswith("armv8"):
            return cls.parse("linux/arm64/v8")
        elif machine.startswith("arm"):
            return cls.parse("linux/arm/v6")
        elif machine.startswith("i686") or machine.startswith("i386"):
            return cls.parse("linux/i386")
        return cls.parse("linux/amd64")

    @classmethod
    def from_payload(cls, payload: Dict[str, str]):
        return cls(
            architecture=payload.get("architecture"),
            os=payload.get("os"),
            variant=payload.get("variant"),
        )

    def match(self, payload: Dict[str, str]) -> bool:
        if self.variant and self.variant != (
            # allows matching linux/arm64 images with linux/arm/v8 requests
            payload.get("variant")
            or self.default_variant(payload.get("architecture"))
        ):
            return False

        return self.os == payload.get("os") and self.architecture == payload.get(
            "architecture"
        )


@dataclass
class Image:
    registry: str
    repository: str
    name: str
    tag: str
    digest: str

    def __str__(self):
        value = f"{self.registry}/{self.repository}/{self.name}:{self.tag}"
        if self.digest:
            value += f"@{self.digest}"
        return value

    @property
    def fullname(self):
        return f"{self.repository}/{self.name}"

    @property
    def reg_fullname(self):
        return f"{self.registry}/{self.fullname}"

    @property
    def fs_name(self):
        return "_".join(pathlib.Path(self.reg_fullname).parts)

    @property
    def reference(self):
        return self.digest or self.tag

    @property
    def url(self):
        domain = (
            "hub.docker.com" if self.registry == "index.docker.io" else self.registry
        )
        prefix = "r/" if self.registry == "index.docker.io" else ""
        return f"https://{domain}/{prefix}/{self.fullname}"

    @classmethod
    def parse(
        cls,
        name: str,
        tag: Optional[str] = None,
        digest: Optional[str] = None,
        repository: Optional[str] = None,
        registry: Optional[str] = None,
        **kwargs,
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
        elif len(tree) == 2:
            registry, repository = tree
        elif len(tree) > 2:
            raise ValueError(f"Unrecognized image tree: {tree}")

        if not repository or repository == "_":
            repository = "library"

        if not registry or registry == "docker.io":
            registry = "index.docker.io"

        name = name_part

        return cls(
            registry=registry, repository=repository, name=name, tag=tag, digest=digest
        )


@dataclass
class RegistryAuth:
    registry: str
    image: str
    token: str
    url: str
    service: str

    @classmethod
    def init(cls, image):
        # default, fallback values
        url = f"https://{image.registry}/token"
        service = ""

        resp = requests.get(f"https://{image.registry}/v2/")
        if resp.status_code == 401:
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
        )

        self.token = resp.json().get("token")

    @property
    def headers(self) -> Dict[str, str]:
        if not self.token:
            self.authenticate()
        return {"Authorization": f"Bearer {self.token}"}


def get_manifests(image, auth):
    """get list of fat-manifests for the image"""
    resp = requests.get(
        f"https://{image.registry}/v2/{image.repository}/{image.name}"
        f"/manifests/{image.reference}",
        headers=dict(
            **auth.headers,
            **{"Accept": "application/vnd.docker.distribution.manifest.list.v2+json"},
        ),
    )
    if resp.status_code == 401:
        raise IOError(
            f"HTTP {resp.status_code}: {resp.reason} -- "
            "This **may** indicate an incorrect image name/registry/repo/tag.\n"
            f"Check {image.url}"
        )
    if resp.status_code == 404:
        raise ValueError(
            f"HTTP {resp.status_code}: {resp.reason} -- "
            f"Image name is probably incorrect.\nCheck {image.url}"
        )
    if resp.status_code != 200:
        raise IOError(f"HTTP {resp.status_code}: {resp.reason} -- {resp.text}")

    return resp.json()


def get_layers_manifest_for(image, auth, reference: str = None):
    """get list of layers for the image using a specific reference"""
    reference = reference or image.reference
    resp = requests.get(
        f"https://{image.registry}/v2/{image.repository}/{image.name}"
        f"/manifests/{reference}",
        headers=dict(
            **auth.headers,
            **{"Accept": "application/vnd.docker.distribution.manifest.v2+json"},
        ),
    )
    if resp.status_code != 200:
        raise IOError("HTTP {resp.status_code}: {resp.reason} -- {resp.text}")

    return resp.json()


def get_layers_from_v1_manifest(
    image: Image, platform: Platform, manifest: Dict
) -> Dict:
    architecture = manifest.get("architecture", "amd64")
    os = manifest.get("os", "linux")

    if not platform.match({"architecture": architecture, "os": os}):
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
            raise V1ImageNotFound(image, platform, is_v1=True)
        manifest = fat_manifests
    else:
        # multi-platform image
        for arch_manifest in fat_manifests.get("manifests", []):
            if platform.match(arch_manifest.get("platform", {})):
                manifest = get_layers_manifest_for(image, auth, arch_manifest["digest"])

        if not manifest:
            platforms = [
                Platform.from_payload(man.get("platform"))
                for man in fat_manifests.get("manifests", [])
            ]
            raise V2ImageNotFound(image, platform, platforms)

    logger.debug(f"layers_manifest={format_json(manifest)}")
    if not manifest.get("layers"):
        raise LayersNotFound(image, platform)
    return manifest


def make_layer_id(parent_id: str, layer: Dict) -> str:
    """Fake layer ID. Don't know how Docker generates it"""
    return hashlib.sha256(
        (parent_id + "\n" + layer["digest"] + "\n").encode("utf-8")
    ).hexdigest()


def get_layer_dir(image_dir: pathlib.Path, layer_id: str) -> pathlib.Path:
    layer_dir = image_dir / layer_id
    layer_dir.mkdir(parents=True, exist_ok=True)
    return layer_dir


def download_layer_blob(
    image: Image, parent_id, layer, layer_dir: pathlib.Path, auth: RegistryAuth
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
    )
    if resp.status_code != 200:  # When the layer is located at a custom URL
        resp = requests.get(
            layer["urls"][0],
            headers=dict(
                **auth.headers,
                **{"Accept": "application/vnd.docker.distribution.manifest.v2+json"},
            ),
            stream=True,
        )
        if resp.status_code != 200:
            raise IOError(
                f"ERROR: Cannot download layer {layer_digest[7:19]} "
                f"[HTTP {resp.status_code}] {resp.headers['Content-Length']}"
            )
    resp.raise_for_status()

    total_exp = int(resp.headers["Content-Length"])
    chunk_size = 1048576
    received = 0
    progress = VisualProgressBar(total_exp) if progressbar else NoProgressBar(total_exp)

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
        unzLayer = gzip.open(layer_dir / "layer_gzip.tar", "rb")
        shutil.copyfileobj(unzLayer, fh)
        unzLayer.close()
    layer_dir.joinpath("layer_gzip.tar").unlink()

    return layer_ark


def write_layer_metadata(
    layer_dir: pathlib.Path, layer_id: str, parent_id: str, layer: Dict, manifest: Dict
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
    manifest: Dict,
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
    manifest: Dict,
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
    )
    if resp.status_code == 404:
        logger.error(
            "Unsupported manifest schema/version: digest blob not found\n\n"
            "###############\n"
            "Use regctl instead https://github.com/regclient/regclient\n"
            f"regctl image export {image} {target}\n"
            "###############\n"
        )
    resp.raise_for_status()
    config = resp.content

    new_manifest = [
        {
            "Config": f"{digest[7:]}.json",
            "RepoTags": [f"{image.reg_fullname}:{image.tag}"],
            "Layers": [],
        }
    ]

    parent_id = ""
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


def export(
    image: Image,
    platform: Platform,
    to: pathlib.Path,
    build_dir: Optional[pathlib.Path] = None,
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
        suffix=".tmp", prefix=to.stem, dir=build_dir, ignore_cleanup_errors=True
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
    if args.get("debug"):
        logger.setLevel(logging.DEBUG)
    try:
        platform = Platform.parse(args["platform"])
        image = Image.parse(**args)
        dest = pathlib.Path(args["output"]).expanduser().resolve()
        if not dest.suffix == ".tar":
            dest = dest.joinpath(f"{image.fs_name}.tar")
        build_dir = (
            pathlib.Path(args["build_dir"]).expanduser().resolve()
            if args.get("build_dir")
            else None
        )
        export(image=image, platform=platform, to=dest, build_dir=build_dir)
        sys.exit(0)
    except Exception as exc:
        logger.error(str(exc))
        if args.get("debug"):
            logger.exception(exc)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
