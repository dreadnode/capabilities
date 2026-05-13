"""
Bootstrap script to install .NET and ILSpy dependencies.

This module handles first-time setup of .NET runtime and ILSpy libraries
in the Dreadnode sandbox environment. Dependencies are installed to the
workspace directory so they persist across sandbox restarts.

Usage:
    from dotnet_agent.bootstrap import ensure_dependencies
    ensure_dependencies()  # Call before importing pythonnet
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

# =============================================================================
# Configuration
# =============================================================================

# Install to workspace so it persists across sandbox restarts.
# /home/user/workspace is S3-mounted and survives sandbox recreation.
# For local runtime, falls back to ~/.dreadnode/deps
SANDBOX_WORKSPACE = Path("/home/user/workspace")
LOCAL_FALLBACK = Path.home() / ".dreadnode" / "deps"


def _get_deps_dir() -> Path:
    """Get the appropriate deps directory based on environment."""
    if SANDBOX_WORKSPACE.exists() and SANDBOX_WORKSPACE.is_dir():
        # Check if it's a mount point (sandbox) or just exists (local dev)
        try:
            if SANDBOX_WORKSPACE.is_mount():
                return SANDBOX_WORKSPACE / ".dreadnode" / "deps"
        except OSError:
            pass
        # If workspace exists but isn't a mount, still use it in sandbox-like envs
        if (SANDBOX_WORKSPACE / ".dreadnode").exists() or os.environ.get("DREADNODE_SANDBOX"):
            return SANDBOX_WORKSPACE / ".dreadnode" / "deps"
    return LOCAL_FALLBACK


DEPS_DIR = _get_deps_dir()
DOTNET_ROOT = DEPS_DIR / "dotnet"
ILSPY_LIB_DIR = DEPS_DIR / "ilspy"

# Versions
DOTNET_CHANNEL = "8.0"
ILSPY_VERSION = "8.2.0.7535"

# Track if bootstrap has run this session
_bootstrapped = False


# =============================================================================
# Public API
# =============================================================================


def ensure_dependencies(verbose: bool = True) -> bool:
    """
    Install .NET and ILSpy if not present. Returns True if ready.

    This function is idempotent - safe to call multiple times.
    Dependencies are installed to a persistent directory so subsequent
    sandbox starts skip the download.

    Args:
        verbose: Print progress messages (default True)

    Returns:
        True if all dependencies are installed and ready

    Raises:
        RuntimeError: If installation fails
    """
    global _bootstrapped
    if _bootstrapped:
        return True

    log = print if verbose else lambda *args, **kwargs: None

    # Create deps directory
    DEPS_DIR.mkdir(parents=True, exist_ok=True)

    # Install components
    if not _is_dotnet_installed():
        log(f"[dotnet-reversing] Installing .NET {DOTNET_CHANNEL} runtime...")
        log("[dotnet-reversing] This is a one-time setup (~100MB download)")
        _install_dotnet()
        log(f"[dotnet-reversing] .NET installed to {DOTNET_ROOT}")

    if not _is_pythonnet_installed():
        log("[dotnet-reversing] Installing pythonnet...")
        _install_pythonnet()
        log("[dotnet-reversing] pythonnet installed")

    if not _is_ilspy_installed():
        log("[dotnet-reversing] Installing ILSpy decompiler libraries...")
        _install_ilspy()
        log(f"[dotnet-reversing] ILSpy installed to {ILSPY_LIB_DIR}")

    # Set environment variables for pythonnet
    os.environ["DOTNET_ROOT"] = str(DOTNET_ROOT)
    os.environ["PATH"] = f"{DOTNET_ROOT}:{os.environ.get('PATH', '')}"
    os.environ["DOTNET_TOOLS_LIB_DIR"] = str(ILSPY_LIB_DIR)

    # Verify installation
    if not (_is_dotnet_installed() and _is_ilspy_installed() and _is_pythonnet_installed()):
        missing = []
        if not _is_dotnet_installed():
            missing.append(".NET runtime")
        if not _is_ilspy_installed():
            missing.append("ILSpy libraries")
        if not _is_pythonnet_installed():
            missing.append("pythonnet")
        raise RuntimeError(f"Bootstrap failed: missing {', '.join(missing)}")

    _bootstrapped = True
    if verbose:
        log("[dotnet-reversing] Bootstrap complete. Ready for .NET reversing.")

    return True


def get_ilspy_lib_dir() -> Path:
    """Return the path to ILSpy libraries."""
    return ILSPY_LIB_DIR


def get_dotnet_root() -> Path:
    """Return the path to .NET runtime."""
    return DOTNET_ROOT


# =============================================================================
# Installation Checks
# =============================================================================


def _is_dotnet_installed() -> bool:
    """Check if .NET runtime is installed."""
    dotnet_exe = DOTNET_ROOT / "dotnet"
    return dotnet_exe.exists() and dotnet_exe.is_file()


def _is_ilspy_installed() -> bool:
    """Check if ILSpy libraries are installed."""
    decompiler_dll = ILSPY_LIB_DIR / "ICSharpCode.Decompiler.dll"
    cecil_dll = ILSPY_LIB_DIR / "Mono.Cecil.dll"
    return decompiler_dll.exists() and cecil_dll.exists()


def _is_pythonnet_installed() -> bool:
    """Check if pythonnet is installed."""
    try:
        import pythonnet  # noqa: F401

        return True
    except ImportError:
        return False


# =============================================================================
# Installation Functions
# =============================================================================


def _run_cmd(cmd: str, error_msg: str, timeout: int = 300) -> None:
    """Run a shell command, raising RuntimeError on failure."""
    result = subprocess.run(
        ["bash", "-c", cmd],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"{error_msg}\n"
            f"Command: {cmd}\n"
            f"Exit code: {result.returncode}\n"
            f"Stdout: {result.stdout}\n"
            f"Stderr: {result.stderr}"
        )


def _install_dotnet() -> None:
    """Install .NET runtime using Microsoft's install script."""
    DOTNET_ROOT.mkdir(parents=True, exist_ok=True)

    cmd = (
        f"curl -fsSL https://dot.net/v1/dotnet-install.sh | "
        f"bash -s -- --channel {DOTNET_CHANNEL} --runtime dotnet --install-dir {DOTNET_ROOT}"
    )
    _run_cmd(cmd, "Failed to install .NET runtime")


def _install_ilspy() -> None:
    """Install ILSpy decompiler libraries from GitHub releases."""
    ILSPY_LIB_DIR.mkdir(parents=True, exist_ok=True)

    # Parse version for download URL (e.g., "8.2.0.7535" -> "8.2")
    parts = ILSPY_VERSION.split(".")
    major, minor = parts[0], parts[1]

    # Download and extract ILSpy binaries
    # Note: ILSpy binaries are cross-platform .NET assemblies, the -x64 suffix
    # refers to the bundled runtime in selfcontained builds, not the DLLs themselves
    cmd = (
        f"curl -fsSL 'https://github.com/icsharpcode/ILSpy/releases/download/"
        f"v{major}.{minor}/ILSpy_binaries_{ILSPY_VERSION}-x64.zip' -o /tmp/ilspy.zip && "
        f"unzip -oq /tmp/ilspy.zip -d /tmp/ilspy && "
        f"cp /tmp/ilspy/ICSharpCode.Decompiler.dll {ILSPY_LIB_DIR}/ && "
        f"cp /tmp/ilspy/Mono.Cecil.dll {ILSPY_LIB_DIR}/ && "
        f"rm -rf /tmp/ilspy /tmp/ilspy.zip"
    )
    _run_cmd(cmd, "Failed to install ILSpy libraries")


def _install_pythonnet() -> None:
    """Install pythonnet package."""
    # When launched via `uv run --with pythonnet`, it's already available.
    # This fallback handles non-uv environments (e.g., sandbox with pip).
    uv_bin = shutil.which("uv")
    if uv_bin:
        cmd = [uv_bin, "pip", "install", "pythonnet>=3.0.5", "--quiet"]
    else:
        cmd = [sys.executable, "-m", "pip", "install", "pythonnet>=3.0.5", "--quiet"]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"Failed to install pythonnet\n"
            f"Command: {' '.join(cmd)}\n"
            f"Stdout: {result.stdout}\n"
            f"Stderr: {result.stderr}"
        )


# =============================================================================
# Fallback: NuGet-based ILSpy installation (requires .NET SDK)
# =============================================================================


def _install_ilspy_via_nuget() -> None:
    """
    Install ILSpy via NuGet restore. Requires .NET SDK.

    Not currently called — retained as a fallback if the GitHub releases
    URL used by ``_install_ilspy()`` becomes unavailable. To use, replace
    the ``_install_ilspy()`` call in ``ensure_dependencies()`` with this.
    """
    # Need the SDK temporarily for `dotnet restore`
    cmd = (
        f"curl -fsSL https://dot.net/v1/dotnet-install.sh | "
        f"bash -s -- --channel {DOTNET_CHANNEL} --install-dir {DOTNET_ROOT}"
    )
    _run_cmd(cmd, "Failed to install .NET SDK")

    dotnet_bin = str(DOTNET_ROOT / "dotnet")
    env = {
        **os.environ,
        "DOTNET_ROOT": str(DOTNET_ROOT),
        "PATH": f"{DOTNET_ROOT}:{os.environ.get('PATH', '')}",
    }

    tmp_dir = Path("/tmp/ilspy-restore")
    tmp_dir.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            [dotnet_bin, "new", "console", "--no-restore"],
            cwd=str(tmp_dir),
            env=env,
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                dotnet_bin,
                "add",
                "package",
                "ICSharpCode.Decompiler",
                "--version",
                ILSPY_VERSION,
            ],
            cwd=str(tmp_dir),
            env=env,
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [dotnet_bin, "restore"],
            cwd=str(tmp_dir),
            env=env,
            check=True,
            capture_output=True,
        )

        ILSPY_LIB_DIR.mkdir(parents=True, exist_ok=True)
        nuget_dir = Path.home() / ".nuget" / "packages"

        # Copy ILSpy + Mono.Cecil DLLs
        for pkg, subpath in [
            ("icsharpcode.decompiler", "net8.0"),
            ("system.reflection.metadata", "net8.0"),
            ("mono.cecil", "netstandard2.0"),
        ]:
            pkg_dir = nuget_dir / pkg
            if not pkg_dir.exists():
                continue
            for dll in pkg_dir.rglob(f"*/{subpath}/*.dll"):
                shutil.copy2(dll, ILSPY_LIB_DIR / dll.name)

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    # Clean up SDK (keep runtime only)
    for d in ["sdk", "templates"]:
        p = DOTNET_ROOT / d
        if p.exists():
            shutil.rmtree(p)
    nuget_cache = Path.home() / ".nuget"
    if nuget_cache.exists():
        shutil.rmtree(nuget_cache)
