"""Tests for multimedia logging tools."""

from __future__ import annotations

from pathlib import Path
import importlib.util

import pytest


MODULE_PATH = Path(__file__).resolve().parent.parent / "tools" / "media_logging.py"
SPEC = importlib.util.spec_from_file_location("media_logging", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

MediaLogging = MODULE.MediaLogging


@pytest.fixture
def toolset() -> MediaLogging:
    return MediaLogging()


@pytest.fixture
def media_files(tmp_path: Path) -> dict[str, Path]:
    image_path = tmp_path / "sample.png"
    image_path.write_bytes(b"png-bytes")

    audio_path = tmp_path / "sample.wav"
    audio_path.write_bytes(b"wav-bytes")

    video_path = tmp_path / "sample.mp4"
    video_path.write_bytes(b"mp4-bytes")

    artifact_path = tmp_path / "notes.txt"
    artifact_path.write_text("artifact", encoding="utf-8")

    return {
        "image": image_path,
        "audio": audio_path,
        "video": video_path,
        "artifact": artifact_path,
    }


class TestToolDiscovery:
    def test_tools_discovered(self, toolset: MediaLogging) -> None:
        names = {tool.name for tool in toolset.get_tools()}
        assert names == {
            "log_image_output",
            "log_audio_output",
            "log_video_output",
            "log_file_artifact",
        }


class TestMediaLogging:
    @pytest.mark.asyncio
    async def test_log_image_output(
        self,
        toolset: MediaLogging,
        media_files: dict[str, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        captured: dict[str, object] = {}

        def fake_log_output(name: str, value: object, **_: object) -> None:
            captured["name"] = name
            captured["value"] = value

        monkeypatch.setattr(MODULE.dn, "log_output", fake_log_output)

        result = await toolset.log_image_output(
            "screenshot/home", str(media_files["image"]), caption="Home"
        )
        assert result == {
            "kind": "image",
            "path": str(media_files["image"]),
            "name": "screenshot/home",
            "caption": "Home",
        }
        assert captured["name"] == "screenshot/home"
        assert isinstance(captured["value"], MODULE.dn.Image)
        assert captured["value"].data == media_files["image"]

    @pytest.mark.asyncio
    async def test_log_audio_output(
        self,
        toolset: MediaLogging,
        media_files: dict[str, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        captured: dict[str, object] = {}

        def fake_log_output(name: str, value: object, **_: object) -> None:
            captured["name"] = name
            captured["value"] = value

        monkeypatch.setattr(MODULE.dn, "log_output", fake_log_output)

        result = await toolset.log_audio_output(
            "audio/sample", str(media_files["audio"]), caption="Sample"
        )
        assert result == {
            "kind": "audio",
            "path": str(media_files["audio"]),
            "name": "audio/sample",
            "caption": "Sample",
        }
        assert captured["name"] == "audio/sample"
        assert isinstance(captured["value"], MODULE.dn.Audio)
        assert captured["value"].data == media_files["audio"]

    @pytest.mark.asyncio
    async def test_log_video_output(
        self,
        toolset: MediaLogging,
        media_files: dict[str, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        captured: dict[str, object] = {}

        def fake_log_output(name: str, value: object, **_: object) -> None:
            captured["name"] = name
            captured["value"] = value

        monkeypatch.setattr(MODULE.dn, "log_output", fake_log_output)

        result = await toolset.log_video_output(
            "video/demo", str(media_files["video"]), caption="Demo"
        )
        assert result == {
            "kind": "video",
            "path": str(media_files["video"]),
            "name": "video/demo",
            "caption": "Demo",
        }
        assert captured["name"] == "video/demo"
        assert isinstance(captured["value"], MODULE.dn.Video)
        assert captured["value"].data == media_files["video"]

    @pytest.mark.asyncio
    async def test_log_file_artifact(
        self,
        toolset: MediaLogging,
        media_files: dict[str, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        captured: dict[str, object] = {}

        def fake_log_artifact(local_uri: object, **kwargs: object) -> None:
            captured["path"] = local_uri
            captured["name"] = kwargs.get("name")

        monkeypatch.setattr(MODULE.dn, "log_artifact", fake_log_artifact)

        result = await toolset.log_file_artifact(
            str(media_files["artifact"]), name="notes.txt"
        )
        assert result == {
            "kind": "artifact",
            "path": str(media_files["artifact"]),
            "name": "notes.txt",
        }
        assert captured["path"] == media_files["artifact"]
        assert captured["name"] == "notes.txt"

    @pytest.mark.asyncio
    async def test_missing_file_raises(self, toolset: MediaLogging) -> None:
        with pytest.raises(FileNotFoundError):
            await toolset.log_image_output("missing", "/tmp/nope.png")

        with pytest.raises(FileNotFoundError):
            await toolset.log_audio_output("missing", "/tmp/nope.wav")

        with pytest.raises(FileNotFoundError):
            await toolset.log_video_output("missing", "/tmp/nope.mp4")

        with pytest.raises(FileNotFoundError):
            await toolset.log_file_artifact("/tmp/nope.bin")

    @pytest.mark.asyncio
    async def test_directory_path_raises(
        self, toolset: MediaLogging, tmp_path: Path
    ) -> None:
        directory = tmp_path / "dir"
        directory.mkdir()

        with pytest.raises(ValueError):
            await toolset.log_file_artifact(str(directory))
