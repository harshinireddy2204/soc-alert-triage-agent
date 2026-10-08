"""Download the public source data at pinned commits.

    python -m triage fetch

* Security Datasets recordings (MIT License), one zip per capture, each checked
  against the SHA-256 recorded in ``benchmark/captures.yaml``.
* The SigmaHQ rule repository (Detection Rule License 1.1) as one archive.
"""

from __future__ import annotations

import hashlib
import io
import shutil
import subprocess
import urllib.error
import urllib.request
import zipfile

from . import paths
from .build import load_captures

USER_AGENT = "soc-alert-triage-agent (benchmark data fetch)"


def _download(url: str, timeout: float = 300.0) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def fetch_captures(log=print) -> None:
    config = load_captures()
    source = config["source"]
    owner_repo = source["repository"].removeprefix("https://github.com/")
    base = f"https://raw.githubusercontent.com/{owner_repo}/{source['commit']}/{source['base_path']}"
    for index, entry in enumerate(config["captures"], start=1):
        target = paths.OTRF_DIR / entry["path"]
        if target.exists() and hashlib.sha256(target.read_bytes()).hexdigest() == entry["sha256"]:
            continue
        data = _download(f"{base}/{entry['path']}")
        digest = hashlib.sha256(data).hexdigest()
        if digest != entry["sha256"]:
            raise RuntimeError(f"{entry['path']}: SHA-256 {digest} does not match the pinned {entry['sha256']}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        log(f"  [{index}/{len(config['captures'])}] {entry['path']} ({len(data) // 1024} KB)")


def _sigma_from_archive(repository: str, commit: str) -> None:
    owner_repo = repository.removeprefix("https://github.com/")
    archive = zipfile.ZipFile(io.BytesIO(_download(f"https://github.com/{owner_repo}/archive/{commit}.zip")))
    wanted = ("rules/", "rules-threat-hunting/", "rules-emerging-threats/", "LICENSE")
    for member in archive.namelist():
        relative = member.split("/", 1)[1] if "/" in member else ""
        if not relative or member.endswith("/") or not relative.startswith(wanted):
            continue
        target = paths.SIGMA_DIR / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(archive.read(member))


def _sigma_from_git(repository: str, commit: str) -> None:
    def git(*arguments: str) -> None:
        subprocess.run(["git", "-C", str(paths.SIGMA_DIR), *arguments], check=True, capture_output=True)

    paths.SIGMA_DIR.mkdir(parents=True, exist_ok=True)
    git("init", "-q")
    git("remote", "add", "origin", repository + ".git")
    git("fetch", "-q", "--depth", "1", "origin", commit)
    git("checkout", "-q", "FETCH_HEAD")


def fetch_sigma(log=print) -> None:
    config = load_captures()["sigma"]
    marker = paths.SIGMA_DIR / ".commit"
    if marker.exists() and marker.read_text().strip() == config["commit"]:
        return
    log(f"  downloading Sigma rules at {config['commit'][:10]}")
    if paths.SIGMA_DIR.exists():
        shutil.rmtree(paths.SIGMA_DIR, ignore_errors=True)
    try:
        _sigma_from_archive(config["repository"], config["commit"])
    except (urllib.error.URLError, zipfile.BadZipFile) as error:
        # Some networks block GitHub's archive downloads; a shallow git fetch gets the same commit.
        log(f"  archive download failed ({error}); falling back to git")
        shutil.rmtree(paths.SIGMA_DIR, ignore_errors=True)
        _sigma_from_git(config["repository"], config["commit"])
    marker.write_text(config["commit"])


def fetch(log=print) -> None:
    log("Fetching Security Datasets recordings")
    fetch_captures(log)
    log("Fetching Sigma rules")
    fetch_sigma(log)
    log(f"Source data is in {paths.DATA}")
