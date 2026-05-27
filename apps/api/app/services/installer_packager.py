"""Package the compiled agent binary together with an install profile."""

from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
import zipfile
from pathlib import Path


class PackagerError(Exception):
    """Raised when the installer package cannot be built."""


# Platform → (binary-name, preferred cross-compile target)
_PLATFORM_BINARY: dict[str, tuple[str, str]] = {
    "windows_msi": ("aetherix-agent.exe", "x86_64-pc-windows-gnu"),
    "windows_exe": ("aetherix-agent.exe", "x86_64-pc-windows-gnu"),
    "macos_pkg": ("aetherix-agent", "x86_64-apple-darwin"),
    "linux_deb": ("aetherix-agent", "x86_64-unknown-linux-gnu"),
    "linux_rpm": ("aetherix-agent", "x86_64-unknown-linux-musl"),
}


def _binary_dir_for_platform(platform: str) -> str:
    """Return the directory containing the compiled agent binary for *platform*.

    Resolution order:
      1. ``AETHERIX_AGENT_BINARY_DIR`` env var (exact path).
      2. ``agent/dist/<platform>/`` (populated by ``agent/build-all.sh``).
      3. ``agent/target/<target>/release/`` (direct Cargo output).
      4. ``agent/target/release/`` (default host target, fallback).
    """
    env_dir = os.getenv("AETHERIX_AGENT_BINARY_DIR")
    if env_dir:
        return env_dir

    entry = _PLATFORM_BINARY.get(platform)
    if entry is None:
        raise PackagerError(f"Unknown platform {platform!r}")

    project_root = Path(__file__).resolve().parents[4]

    # Prefer dist/ layout (populated by build-all.sh)
    dist_dir = project_root / "agent" / "dist" / platform
    if dist_dir.is_dir():
        return str(dist_dir)

    # Then cross-compile target directory
    _, cross_target = entry
    target_dir = project_root / "agent" / "target" / cross_target / "release"
    if target_dir.is_dir():
        return str(target_dir)

    # Fall back to default host target
    return str(project_root / "agent" / "target" / "release")


def package_installer(
    platform: str,
    install_profile: dict[str, object],
) -> tuple[bytes, str, str]:
    """Package the compiled agent binary with *install_profile*.

    Returns ``(package_bytes, filename, sha256_hex)``.
    """
    entry = _PLATFORM_BINARY.get(platform)
    if entry is None:
        raise PackagerError(f"Unknown platform {platform!r}")

    binary_name, _ = entry
    binary_dir = _binary_dir_for_platform(platform)
    binary_path = os.path.join(binary_dir, binary_name)
    if not os.path.isfile(binary_path):
        # Graceful fallback: check if alternative extension binary exists in the same resolved folder
        alt_name = "aetherix-agent" if binary_name.endswith(".exe") else "aetherix-agent.exe"
        alt_path = os.path.join(binary_dir, alt_name)
        if os.path.isfile(alt_path):
            binary_path = alt_path
        else:
            raise PackagerError(
                f"Agent binary not found at {binary_path} "
                f"(set AETHERIX_AGENT_BINARY_DIR to override)"
            )

    profile_bytes = json.dumps(install_profile, indent=2).encode("utf-8")

    if platform.startswith("windows_"):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(binary_path, arcname=binary_name)
            zf.writestr("install-profile.json", profile_bytes)
        package_bytes = buf.getvalue()
        filename = f"aetherix-agent-{platform}.zip"
    else:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            tar.add(binary_path, arcname=binary_name)
            info = tarfile.TarInfo(name="install-profile.json")
            info.size = len(profile_bytes)
            tar.addfile(info, io.BytesIO(profile_bytes))
        package_bytes = buf.getvalue()
        filename = f"aetherix-agent-{platform}.tar.gz"

    sha256 = hashlib.sha256(package_bytes).hexdigest()
    return package_bytes, filename, sha256
