"""Tests for the multimodal media manifest builder."""

from __future__ import annotations

import importlib.util
from pathlib import Path

MANIFEST_PATH = Path(__file__).resolve().parents[1] / "scripts" / "media_manifest.py"


def _load():
    spec = importlib.util.spec_from_file_location("media_manifest", MANIFEST_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mm = _load()


def _write_png(path: Path) -> None:
    from PIL import Image as PILImage

    PILImage.new("RGB", (32, 16), (10, 20, 30)).save(path)


class TestBuildManifest:
    def test_errors_without_media(self, tmp_path) -> None:
        res = mm.build_manifest({"directory": str(tmp_path)})
        assert "error" in res

    def test_inventories_directory_and_excludes_non_media(self, tmp_path) -> None:
        _write_png(tmp_path / "a.png")
        (tmp_path / "clip.mp3").write_bytes(b"ID3data")
        (tmp_path / "notes.txt").write_text("ignore me")

        res = mm.build_manifest({"directory": str(tmp_path)})
        assert "error" not in res
        assert res["count"] == 2
        assert res["by_kind"] == {"image": 1, "audio": 1}
        paths = [i["path"] for i in res["items"]]
        assert not any(p.endswith(".txt") for p in paths)

    def test_image_dimensions_present_no_bytes(self, tmp_path) -> None:
        _write_png(tmp_path / "a.png")
        res = mm.build_manifest({"paths": [str(tmp_path / "a.png")]})
        img = res["items"][0]
        assert img["kind"] == "image"
        assert img["mime"] == "image/png"
        assert img["dims"] == [32, 16]
        # A manifest is a reference — it must never carry raw bytes/base64.
        assert "data" not in img and "base64" not in img
        assert img["bytes"] > 0

    def test_dispatch_unknown_method(self) -> None:
        assert "error" in mm.METHODS["build_media_manifest"]({"directory": "/nonexistent"})
