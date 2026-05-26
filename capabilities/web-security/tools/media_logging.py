"""Typed multimedia logging helpers for Dreadnode runs.

These tools mirror the old v1 ``web-agent`` screenshot-ingest idea while using
the current SDK primitives directly. They accept existing local files and log
them either as typed outputs (`Image`, `Audio`, `Video`) or as uploaded
artifacts.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any

import dreadnode as dn
from dreadnode.agents.tools import Toolset, tool_method


def _existing_file(path: str) -> Path:
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"File does not exist: {file_path}")
    if not file_path.is_file():
        raise ValueError(f"Path is not a file: {file_path}")
    return file_path


def _result(
    kind: str, path: Path, name: str | None = None, caption: str | None = None
) -> dict[str, Any]:
    result: dict[str, Any] = {"kind": kind, "path": str(path)}
    if name:
        result["name"] = name
    if caption:
        result["caption"] = caption
    return result


class MediaLogging(Toolset):
    """Log images, audio, video, and arbitrary files to the current Dreadnode run."""

    @tool_method(name="log_image_output", catch=True)
    async def log_image_output(
        self,
        name: Annotated[str, "Output name to log under the current task or run."],
        path: Annotated[str, "Path to an existing local image file."],
        caption: Annotated[
            str | None, "Optional caption shown with the image output."
        ] = None,
    ) -> dict[str, Any]:
        """Log an existing image file as a typed Dreadnode output."""
        file_path = _existing_file(path)
        dn.log_output(name, dn.Image(file_path, caption=caption))
        return _result("image", file_path, name=name, caption=caption)

    @tool_method(name="log_audio_output", catch=True)
    async def log_audio_output(
        self,
        name: Annotated[str, "Output name to log under the current task or run."],
        path: Annotated[str, "Path to an existing local audio file."],
        caption: Annotated[
            str | None, "Optional caption shown with the audio output."
        ] = None,
    ) -> dict[str, Any]:
        """Log an existing audio file as a typed Dreadnode output."""
        file_path = _existing_file(path)
        dn.log_output(name, dn.Audio(file_path, caption=caption))
        return _result("audio", file_path, name=name, caption=caption)

    @tool_method(name="log_video_output", catch=True)
    async def log_video_output(
        self,
        name: Annotated[str, "Output name to log under the current task or run."],
        path: Annotated[str, "Path to an existing local video file."],
        caption: Annotated[
            str | None, "Optional caption shown with the video output."
        ] = None,
    ) -> dict[str, Any]:
        """Log an existing video file as a typed Dreadnode output."""
        file_path = _existing_file(path)
        dn.log_output(name, dn.Video(file_path, caption=caption))
        return _result("video", file_path, name=name, caption=caption)

    @tool_method(name="log_file_artifact", catch=True)
    async def log_file_artifact(
        self,
        path: Annotated[
            str, "Path to an existing local file to upload as an artifact."
        ],
        name: Annotated[str | None, "Optional artifact name override."] = None,
    ) -> dict[str, Any]:
        """Upload an existing local file as a Dreadnode artifact."""
        file_path = _existing_file(path)
        dn.log_artifact(file_path, name=name)
        return _result("artifact", file_path, name=name)
