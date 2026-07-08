"""Generate typographic / visual prompt-injection images for multimodal probing.

Renders attacker-supplied text onto an image — a common visual-prompt-injection
technique ("typographic jailbreak"). The harmful content is the caller-supplied
text; this only rasterizes it so the agent can pass image PATHS to
generate_multimodal_attack WITHOUT loading raw media into its context.

Dispatched by the generate_injection_images tool via JSON stdin/stdout (mirrors
media_manifest.py). Never returns image bytes — only file paths + a summary.
"""

import csv
import json
import sys
from pathlib import Path


def _load_texts(params: dict) -> list[str]:
    texts = [str(t).strip() for t in (params.get("texts") or []) if str(t).strip()]
    csv_path = params.get("texts_csv")
    if csv_path:
        with open(Path(csv_path).expanduser(), newline="", encoding="utf-8") as f:
            for row in csv.reader(f):
                if row and row[0].strip():
                    texts.append(row[0].strip())
    return texts


def render_injection_images(params: dict) -> dict:
    """Render each text as a typographic prompt-injection image; return the paths."""
    texts = _load_texts(params)
    if not texts:
        return {"error": "no texts provided (use texts=[...] or texts_csv=<path>)"}

    out_dir = Path(params.get("output_dir") or "./injection_images").expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)
    width = int(params.get("width", 1024))
    height = int(params.get("height", 1024))
    font_size = int(params.get("font_size", 40))
    bg = params.get("background", "white")
    fg = params.get("foreground", "black")
    base_image = params.get("base_image")

    from PIL import Image, ImageDraw, ImageFont

    try:
        font = ImageFont.truetype("DejaVuSans.ttf", font_size)
    except Exception:
        font = ImageFont.load_default()

    written: list[str] = []
    for i, text in enumerate(texts):
        if base_image:
            img = Image.open(base_image).convert("RGB").resize((width, height))
        else:
            img = Image.new("RGB", (width, height), bg)
        draw = ImageDraw.Draw(img)

        # Greedy word-wrap to the image width.
        lines: list[str] = []
        cur = ""
        for word in text.split():
            trial = (cur + " " + word).strip()
            if draw.textlength(trial, font=font) <= width - 40:
                cur = trial
            else:
                if cur:
                    lines.append(cur)
                cur = word
        if cur:
            lines.append(cur)

        y = 20
        for line in lines:
            draw.text((20, y), line, fill=fg, font=font)
            y += int(font_size * 1.3)

        path = out_dir / "injection_{:03d}.png".format(i)
        img.save(path)
        written.append(str(path))

    preview = written[:3]
    more = "..." if len(written) > 3 else ""
    return {
        "output_dir": str(out_dir),
        "count": len(written),
        "paths": written,
        "summary": (
            "Rendered {} injection image(s) into {}. Pass image_dir='{}' (or "
            "image_paths={}{}) to generate_multimodal_attack.".format(
                len(written), out_dir, out_dir, preview, more
            )
        ),
    }


METHODS = {"generate_injection_images": render_injection_images}


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
