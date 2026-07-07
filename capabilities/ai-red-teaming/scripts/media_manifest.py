"""
Media manifest for multimodal red teaming.

Builds a token-efficient *reference* inventory of a folder (or list) of media files so
the orchestrating agent can plan an attack without loading raw bytes into its context.
One compact record per file: kind / mime / size / dimensions (+ a cheap ``has_text`` flag
for images). Bytes are never included — the agent references files by path and only the
attack runner and target model ever load the actual media.

Invoked via the same stdin/stdout JSON dispatch as attack_runner (tool: build_media_manifest).
"""

import json
import sys
from pathlib import Path

_MEDIA_EXTS = {
    ".png": ("image", "image/png"),
    ".jpg": ("image", "image/jpeg"),
    ".jpeg": ("image", "image/jpeg"),
    ".gif": ("image", "image/gif"),
    ".webp": ("image", "image/webp"),
    ".bmp": ("image", "image/bmp"),
    ".mp3": ("audio", "audio/mpeg"),
    ".wav": ("audio", "audio/wav"),
    ".ogg": ("audio", "audio/ogg"),
    ".flac": ("audio", "audio/flac"),
    ".m4a": ("audio", "audio/mp4"),
    ".mp4": ("video", "video/mp4"),
    ".webm": ("video", "video/webm"),
    ".mov": ("video", "video/quicktime"),
    ".mkv": ("video", "video/x-matroska"),
}


def _iter_files(paths: list[str], directory: str | None) -> list[Path]:
    out: list[Path] = []
    for p in paths or []:
        fp = Path(p).expanduser()
        if fp.is_file():
            out.append(fp)
    if directory:
        d = Path(directory).expanduser()
        if d.is_dir():
            out.extend(sorted(f for f in d.rglob("*") if f.is_file()))
    # De-dup preserving order
    seen: set[str] = set()
    uniq: list[Path] = []
    for f in out:
        key = str(f.resolve())
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    return uniq


def _image_meta(path: Path) -> dict:
    """Cheap image dimensions + a heuristic has_text flag (no OCR dependency)."""
    meta: dict = {}
    try:
        from PIL import Image as PILImage

        with PILImage.open(path) as im:
            meta["dims"] = [im.width, im.height]
            if im.height:
                meta["aspect"] = round(im.width / im.height, 3)
    except Exception:
        pass
    # has_text is left null unless a cheap OCR is available — the agent should
    # invoke a vision tool lazily only when a *semantic* transform needs it.
    meta["has_text"] = None
    return meta


def build_manifest(params: dict) -> dict:
    """Build a reference manifest for the given media paths/directory."""
    paths = params.get("paths") or []
    directory = params.get("directory") or params.get("media_dir") or ""

    files = _iter_files(paths, directory or None)
    if not files:
        return {"error": "No media files found. Provide 'paths' and/or 'directory'."}

    items: list[dict] = []
    by_kind: dict[str, int] = {}
    for idx, f in enumerate(files):
        kind, mime = _MEDIA_EXTS.get(f.suffix.lower(), (None, None))
        if kind is None:
            continue  # skip non-media
        by_kind[kind] = by_kind.get(kind, 0) + 1
        rec: dict = {
            "id": "{}_{:03d}".format(kind, idx),
            "path": str(f),
            "kind": kind,
            "mime": mime,
            "bytes": f.stat().st_size,
        }
        if kind == "image":
            rec.update(_image_meta(f))
        items.append(rec)

    if not items:
        return {"error": "Found files but none were recognized media types."}

    # Token-efficient summary so the agent can plan over homogeneous sets.
    summary = ", ".join("{} {}".format(n, k) for k, n in sorted(by_kind.items()))

    return {
        "count": len(items),
        "by_kind": by_kind,
        "summary": summary,
        "items": items,
        "note": (
            "Reference manifest only — no bytes loaded. Choose modality-typed transforms "
            "from the technique map and pass the paths/dir to generate_multimodal_attack. "
            "Invoke a vision tool only if a semantic transform (e.g. visual prompt injection) "
            "needs to know what the media depicts."
        ),
    }


METHODS = {"build_media_manifest": build_manifest}


def main() -> None:
    request = json.loads(sys.stdin.read())
    method = request.get("name", request.get("method", ""))
    params = request.get("parameters", {})
    handler = METHODS.get(method)
    if not handler:
        print(json.dumps({"error": "Unknown method: {}".format(method)}))
        sys.exit(1)
    try:
        print(json.dumps(handler(params)))
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"error": str(e)}))
        sys.exit(1)


if __name__ == "__main__":
    main()
