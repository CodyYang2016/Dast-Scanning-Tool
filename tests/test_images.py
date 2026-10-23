"""NTR only: on the Nationwide workstation every image comes from the internal mirror.

`scripts/images.sh` works out each image from versions.lock. With DAST_IMAGE_MIRROR set it names
every image under the mirror and refuses any that isn't; without it, it changes nothing, so Docker
and every default behave as before. `scripts/check_images.sh` lists what each path needs.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
MIRROR = "ntr.nwie.net"
VARS = {"ZAP_IMAGE": "zap_image", "JUICE_IMAGE": "juice_shop_image", "DVWA_IMAGE": "dvwa_image",
        "WEBGOAT_IMAGE": "webgoat_image", "RUNNER_BASE_IMAGE": "runner_base_image"}


def _bash():
    if os.name == "nt":            # Git Bash, not WSL's bash.exe
        for p in (r"C:\Program Files\Git\bin\bash.exe", r"C:\Program Files\Git\usr\bin\bash.exe"):
            if os.path.exists(p):
                return p
        return None
    return shutil.which("bash")


BASH = _bash()
needs_bash = pytest.mark.skipif(BASH is None, reason="needs bash (Git Bash on Windows)")


def _lock() -> dict:
    out = {}
    for line in (ROOT / "versions.lock").read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.startswith("#") and ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def _qualified(ref: str) -> str:
    first = ref.split("/", 1)[0]
    return ref if ("." in first or ":" in first or first == "localhost") else f"docker.io/{ref}"


def _env(**extra):
    base = {k: v for k, v in os.environ.items() if k not in VARS and k != "DAST_IMAGE_MIRROR"}
    return {**base, **extra}


def _source(**extra):
    """Source scripts/images.sh in a clean shell and return (exit code, exported images, stderr)."""
    script = 'source scripts/images.sh || exit $?; for v in ' + " ".join(VARS) + '; do echo "$v=${!v-}"; done'
    r = subprocess.run([BASH, "-c", script], cwd=ROOT, env=_env(**extra), capture_output=True,
                       text=True, encoding="utf-8", timeout=60)
    images = dict(line.split("=", 1) for line in r.stdout.splitlines() if "=" in line)
    return r.returncode, images, r.stderr


# ── the helper ────────────────────────────────────────────────────────────────────────────

@needs_bash
def test_without_a_mirror_nothing_is_exported():
    code, images, err = _source()
    assert code == 0, err
    assert all(v == "" for v in images.values()), images


@needs_bash
def test_with_the_mirror_every_image_is_under_ntr_and_keeps_its_pin():
    code, images, err = _source(DAST_IMAGE_MIRROR=MIRROR)
    assert code == 0, err
    lock = _lock()
    for var, key in VARS.items():
        assert images[var] == f"{MIRROR}/{_qualified(lock[key])}", (var, images[var])
    assert images["ZAP_IMAGE"].startswith("ntr.nwie.net/docker.io/zaproxy/zap-stable@sha256:")
    assert images["RUNNER_BASE_IMAGE"] == "ntr.nwie.net/mcr.microsoft.com/playwright/python:v1.62.0-jammy"


@needs_bash
def test_an_explicit_image_wins():
    code, images, err = _source(DAST_IMAGE_MIRROR=MIRROR, ZAP_IMAGE="ntr.nwie.net/docker.io/zaproxy/zap-stable")
    assert code == 0, err
    assert images["ZAP_IMAGE"] == "ntr.nwie.net/docker.io/zaproxy/zap-stable"


@needs_bash
def test_with_the_mirror_an_image_from_elsewhere_is_refused():
    code, _, err = _source(DAST_IMAGE_MIRROR=MIRROR, JUICE_IMAGE="docker.io/bkimminich/juice-shop")
    assert code != 0
    assert "JUICE_IMAGE" in err and "ntr.nwie.net/" in err


# ── one source of truth: versions.lock ────────────────────────────────────────────────────

def test_compose_defaults_match_versions_lock():
    lock = _lock()
    base = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))
    default = lambda s: re.fullmatch(r"\$\{[A-Z_]+:-(.+)\}", s).group(1)   # noqa: E731
    for svc, key in (("zap", "zap_image"), ("juice", "juice_shop_image"),
                     ("dvwa", "dvwa_image"), ("webgoat", "webgoat_image")):
        assert default(base["services"][svc]["image"]) == _qualified(lock[key]), svc
    for svc in ("runner", "semgate"):
        assert default(base["services"][svc]["build"]["args"]["BASE_IMAGE"]) == lock["runner_base_image"], svc


def test_replay_script_defaults_match_versions_lock():
    text = (ROOT / "demo_replay_flow.sh").read_text(encoding="utf-8")
    assert "source " in text and "scripts/images.sh" in text
    assert "--build-arg \"BASE_IMAGE=" in text
    assert "sha256:" not in text            # no second copy of a digest to drift


def test_containerfiles_build_from_the_locked_base_by_default():
    base = _lock()["runner_base_image"]
    for name in ("Containerfile", "Containerfile.lab"):
        lines = (ROOT / name).read_text(encoding="utf-8").splitlines()
        assert f"ARG BASE_IMAGE={base}" in lines, name
        assert [ln for ln in lines if ln.startswith("FROM ")] == ["FROM ${BASE_IMAGE}"], name


def test_prepull_pulls_the_resolved_base_image():
    text = (ROOT / "prepull_playwright_podman_nationwide.sh").read_text(encoding="utf-8")
    assert "scripts/images.sh" in text
    assert re.search(r'IMAGE="\$\{PLAYWRIGHT_IMAGE:-\$\{RUNNER_BASE_IMAGE', text)


# ── the check ─────────────────────────────────────────────────────────────────────────────

@needs_bash
def test_check_images_lists_every_image_with_its_ntr_name_and_who_needs_it():
    r = subprocess.run([BASH, "scripts/check_images.sh", "--dry-run"], cwd=ROOT,
                       env=_env(DAST_IMAGE_MIRROR=MIRROR), capture_output=True, text=True,
                       encoding="utf-8", timeout=60)
    assert r.returncode == 0, r.stderr
    for var in VARS:
        assert var in r.stdout
    assert r.stdout.count("ntr.nwie.net/") >= len(VARS)
    assert "web UI" in r.stdout and "full scan" in r.stdout


@needs_bash
def test_check_images_without_a_mirror_says_so():
    r = subprocess.run([BASH, "scripts/check_images.sh", "--dry-run"], cwd=ROOT, env=_env(),
                       capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert r.returncode == 0, r.stderr
    assert "DAST_IMAGE_MIRROR" in r.stdout
