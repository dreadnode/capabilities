"""Tests for exiftool wrapper tools."""

from __future__ import annotations

import asyncio
import importlib.util
import sys
import types
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest


def _install_dreadnode_tools_stub() -> None:
    existing = sys.modules.get("dreadnode.agents.tools")
    if existing is not None and hasattr(existing, "FunctionCall"):
        return

    dreadnode = types.ModuleType("dreadnode")
    agents = types.ModuleType("dreadnode.agents")
    tools = types.ModuleType("dreadnode.agents.tools")

    class _Tool:
        def __init__(self, name: str, description: str, catch: bool) -> None:
            self.name = name
            self.description = description
            self.catch = catch
            self.parameters_schema = {"properties": {}}

    def tool_method(*, name: str, catch: bool = False):
        def decorator(fn):
            fn._tool_metadata = {
                "name": name,
                "catch": catch,
                "description": fn.__doc__ or "",
            }
            return fn

        return decorator

    class Toolset:
        def get_tools(self):
            discovered = []
            for attr_name in dir(self):
                value = getattr(self, attr_name)
                meta = getattr(value, "_tool_metadata", None)
                if meta:
                    discovered.append(
                        _Tool(meta["name"], meta["description"], meta["catch"])
                    )
            return discovered

    tools.Toolset = Toolset
    tools.tool_method = tool_method
    agents.tools = tools
    dreadnode.agents = agents

    sys.modules["dreadnode"] = dreadnode
    sys.modules["dreadnode.agents"] = agents
    sys.modules["dreadnode.agents.tools"] = tools


_install_dreadnode_tools_stub()

MODULE_PATH = Path(__file__).resolve().parent.parent / "tools" / "exiftool.py"
SPEC = importlib.util.spec_from_file_location("exiftool", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

ExifTool = MODULE.ExifTool


@pytest.fixture
def toolset() -> ExifTool:
    return ExifTool()


def _mock_process(stdout: str = "", stderr: str = "", returncode: int = 0):
    """Create a mock subprocess for asyncio.create_subprocess_exec."""
    proc = AsyncMock()
    proc.communicate = AsyncMock(return_value=(stdout.encode(), stderr.encode()))
    proc.returncode = returncode
    proc.kill = AsyncMock()
    return proc


class TestToolDiscovery:
    def test_tools_discovered(self, toolset: ExifTool) -> None:
        names = {tool.name for tool in toolset.get_tools()}
        assert names == {"exif_read", "exif_write", "exif_strip", "exif_copy"}


class TestExifRead:
    @pytest.mark.asyncio
    async def test_read_file_not_found(self, toolset: ExifTool) -> None:
        result = await toolset.exif_read("/nonexistent/file.jpg")
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_read_all_tags(self, toolset: ExifTool, tmp_path: Path) -> None:
        img = tmp_path / "test.jpg"
        img.write_bytes(b"\xff\xd8\xff\xe0")  # minimal JPEG header

        mock_proc = _mock_process(stdout='[{"File:FileName": "test.jpg"}]')
        with (
            patch("shutil.which", return_value="/usr/bin/exiftool"),
            patch("asyncio.create_subprocess_exec", return_value=mock_proc),
        ):
            result = await toolset.exif_read(str(img))
        assert "test.jpg" in result

    @pytest.mark.asyncio
    async def test_read_specific_tags(self, toolset: ExifTool, tmp_path: Path) -> None:
        img = tmp_path / "test.jpg"
        img.write_bytes(b"\xff\xd8\xff\xe0")

        mock_proc = _mock_process(stdout='[{"EXIF:Comment": "hello"}]')
        with (
            patch("shutil.which", return_value="/usr/bin/exiftool"),
            patch(
                "asyncio.create_subprocess_exec", return_value=mock_proc
            ) as mock_exec,
        ):
            result = await toolset.exif_read(str(img), tags=["Comment"])
        # Verify -Comment flag was passed
        call_args = mock_exec.call_args[0]
        assert "-Comment" in call_args
        assert "hello" in result


class TestExifWrite:
    @pytest.mark.asyncio
    async def test_write_file_not_found(self, toolset: ExifTool) -> None:
        result = await toolset.exif_write("/nonexistent/file.jpg", {"Comment": "test"})
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_write_tags(self, toolset: ExifTool, tmp_path: Path) -> None:
        img = tmp_path / "test.jpg"
        img.write_bytes(b"\xff\xd8\xff\xe0")

        mock_proc = _mock_process(stdout="1 image files updated")
        with (
            patch("shutil.which", return_value="/usr/bin/exiftool"),
            patch(
                "asyncio.create_subprocess_exec", return_value=mock_proc
            ) as mock_exec,
        ):
            result = await toolset.exif_write(
                str(img), {"Comment": "<script>alert(1)</script>", "Artist": "attacker"}
            )
        call_args = mock_exec.call_args[0]
        assert "-Comment=<script>alert(1)</script>" in call_args
        assert "-Artist=attacker" in call_args
        assert "-overwrite_original" in call_args
        assert "updated" in result

    @pytest.mark.asyncio
    async def test_write_with_backup(self, toolset: ExifTool, tmp_path: Path) -> None:
        img = tmp_path / "test.jpg"
        img.write_bytes(b"\xff\xd8\xff\xe0")

        mock_proc = _mock_process(stdout="1 image files updated")
        with (
            patch("shutil.which", return_value="/usr/bin/exiftool"),
            patch(
                "asyncio.create_subprocess_exec", return_value=mock_proc
            ) as mock_exec,
        ):
            await toolset.exif_write(str(img), {"Comment": "test"}, no_backup=False)
        call_args = mock_exec.call_args[0]
        assert "-overwrite_original" not in call_args


class TestExifStrip:
    @pytest.mark.asyncio
    async def test_strip_file_not_found(self, toolset: ExifTool) -> None:
        result = await toolset.exif_strip("/nonexistent/file.jpg")
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_strip_all(self, toolset: ExifTool, tmp_path: Path) -> None:
        img = tmp_path / "test.jpg"
        img.write_bytes(b"\xff\xd8\xff\xe0")

        mock_proc = _mock_process(stdout="1 image files updated")
        with (
            patch("shutil.which", return_value="/usr/bin/exiftool"),
            patch(
                "asyncio.create_subprocess_exec", return_value=mock_proc
            ) as mock_exec,
        ):
            result = await toolset.exif_write(str(img), {"Comment": "test"})
        assert "updated" in result


class TestExifCopy:
    @pytest.mark.asyncio
    async def test_copy_source_not_found(
        self, toolset: ExifTool, tmp_path: Path
    ) -> None:
        dst = tmp_path / "dst.jpg"
        dst.write_bytes(b"\xff\xd8\xff\xe0")
        result = await toolset.exif_copy("/nonexistent/src.jpg", str(dst))
        assert "source" in result.lower() and "Error" in result

    @pytest.mark.asyncio
    async def test_copy_dest_not_found(self, toolset: ExifTool, tmp_path: Path) -> None:
        src = tmp_path / "src.jpg"
        src.write_bytes(b"\xff\xd8\xff\xe0")
        result = await toolset.exif_copy(str(src), "/nonexistent/dst.jpg")
        assert "destination" in result.lower() and "Error" in result

    @pytest.mark.asyncio
    async def test_copy_tags(self, toolset: ExifTool, tmp_path: Path) -> None:
        src = tmp_path / "src.jpg"
        dst = tmp_path / "dst.jpg"
        src.write_bytes(b"\xff\xd8\xff\xe0")
        dst.write_bytes(b"\xff\xd8\xff\xe0")

        mock_proc = _mock_process(stdout="1 image files updated")
        with (
            patch("shutil.which", return_value="/usr/bin/exiftool"),
            patch(
                "asyncio.create_subprocess_exec", return_value=mock_proc
            ) as mock_exec,
        ):
            result = await toolset.exif_copy(str(src), str(dst))
        call_args = mock_exec.call_args[0]
        assert "-TagsFromFile" in call_args
        assert "updated" in result


class TestExifToolNotFound:
    @pytest.mark.asyncio
    async def test_missing_exiftool(self, toolset: ExifTool, tmp_path: Path) -> None:
        img = tmp_path / "test.jpg"
        img.write_bytes(b"\xff\xd8\xff\xe0")

        with patch("shutil.which", return_value=None):
            with pytest.raises(FileNotFoundError, match="exiftool not found"):
                await toolset.exif_read(str(img))
