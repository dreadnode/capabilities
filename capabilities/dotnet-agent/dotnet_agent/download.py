"""
NuGet package downloader.

Downloads and extracts NuGet packages for .NET binary analysis.
Stripped of Ray/Kafka dependencies — operates as a simple async function.
"""

import io
import zipfile
from pathlib import Path

import aiohttp
from loguru import logger

NUGET_BASE_URL = "https://api.nuget.org/v3-flatcontainer"
DEFAULT_OUTPUT_DIR = Path("/home/user/workspace/nuget")


async def download_nuget_package(
    package: str,
    output_dir: Path | None = None,
    version: str | None = None,
) -> Path:
    """
    Download and extract a NuGet package.

    Args:
        package: NuGet package name (e.g. "Newtonsoft.Json").
        output_dir: Directory to extract into. Defaults to /home/user/workspace/nuget.
        version: Specific version to download. Defaults to latest.

    Returns:
        Path to the extracted package directory.
    """
    output_dir = output_dir or DEFAULT_OUTPUT_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    package_lower = package.lower()

    async with aiohttp.ClientSession() as client:
        # Get package versions
        async with client.get(
            f"{NUGET_BASE_URL}/{package_lower}/index.json",
        ) as response:
            if response.status != 200:
                raise RuntimeError(
                    f"Failed to fetch package {package} from NuGet (status {response.status})"
                )

            data = await response.json()
            versions = data["versions"]
            target_version = version or versions[-1]
            logger.info(f"Downloading {package} v{target_version}")

        extract_dir = output_dir / f"{package_lower}.{target_version}"

        if extract_dir.exists():
            logger.info(f"Package already extracted at {extract_dir}")
            return extract_dir

        # Download the .nupkg
        nupkg_url = (
            f"{NUGET_BASE_URL}/{package_lower}/{target_version}/"
            f"{package_lower}.{target_version}.nupkg"
        )
        async with client.get(nupkg_url) as response:
            if response.status != 200:
                raise RuntimeError(
                    f"Failed to download {package} v{target_version} (status {response.status})"
                )

            data = await response.read()
            with (
                io.BytesIO(data) as buffer,
                zipfile.ZipFile(buffer) as zip_file,
            ):
                zip_file.extractall(extract_dir)

            logger.info(f"Extracted to {extract_dir}")

    return extract_dir
