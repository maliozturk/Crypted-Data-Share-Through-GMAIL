from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw


ROOT = Path(__file__).resolve().parents[1]
ASSETS_DIR = ROOT / "src" / "crypted_mail" / "assets"
PNG_PATH = ASSETS_DIR / "crypted_mail.png"
ICO_PATH = ASSETS_DIR / "crypted_mail.ico"


def main() -> None:
    ASSETS_DIR.mkdir(parents=True, exist_ok=True)
    size = 256
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    draw.rounded_rectangle((20, 20, 236, 236), radius=52, fill="#1f3a5f")
    draw.rounded_rectangle((32, 32, 224, 224), radius=44, outline="#c25d2e", width=8)
    draw.rounded_rectangle((56, 90, 200, 176), radius=22, fill="#fbf8f2")
    draw.line((64, 102, 128, 146, 192, 102), fill="#1f3a5f", width=14, joint="curve")
    draw.arc((92, 44, 164, 118), start=180, end=360, fill="#f3b562", width=16)
    draw.ellipse((116, 116, 140, 140), fill="#c25d2e")
    draw.line((128, 140, 128, 160), fill="#c25d2e", width=10)

    image.save(PNG_PATH)
    image.save(ICO_PATH, sizes=[(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)])


if __name__ == "__main__":
    main()
