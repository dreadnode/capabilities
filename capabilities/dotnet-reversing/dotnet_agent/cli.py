"""
CLI for the dotnet capability package.

Install/uninstall the .NET analysis capability into dreadcode's
capabilities directory so it gets auto-discovered at startup.

Usage:
    dotnet-capability install     # symlink into ~/.dreadnode/capabilities/dotnet/
    dotnet-capability uninstall   # remove the symlink
"""

import os
import sys
from pathlib import Path


def _capabilities_dir() -> Path:
    return Path(os.environ.get("DREADNODE_CAPABILITIES_DIR", Path.home() / ".dreadnode" / "capabilities"))


def _capability_path() -> Path:
    """Path to this package's capability files (capability.yaml, tool.py)."""
    return Path(__file__).parent


def install() -> None:
    target = _capabilities_dir() / "dotnet"
    source = _capability_path()

    target.parent.mkdir(parents=True, exist_ok=True)

    if target.is_symlink() or target.exists():
        if target.is_symlink() and target.resolve() == source.resolve():
            print(f"Already installed: {target} -> {source}")
            return
        print(f"Removing existing {target}")
        if target.is_symlink():
            target.unlink()
        else:
            import shutil

            shutil.rmtree(target)

    target.symlink_to(source)
    print(f"Installed: {target} -> {source}")


def uninstall() -> None:
    target = _capabilities_dir() / "dotnet"

    if not target.exists() and not target.is_symlink():
        print("Not installed.")
        return

    if target.is_symlink():
        target.unlink()
    else:
        import shutil

        shutil.rmtree(target)

    print(f"Removed: {target}")


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] not in ("install", "uninstall"):
        print("Usage: dotnet-capability <install|uninstall>")
        sys.exit(1)

    if sys.argv[1] == "install":
        install()
    else:
        uninstall()


if __name__ == "__main__":
    main()
