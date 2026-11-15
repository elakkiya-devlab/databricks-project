from pathlib import Path

from PIL import Image, ImageDraw


def main():
    image = Image.new("RGBA", (160, 160), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.polygon([(80, 8), (137, 30), (130, 99), (109, 127), (80, 149), (51, 127), (30, 99), (23, 30)], fill="#167a72")
    draw.line([(53, 54), (107, 107)], fill="white", width=13)
    draw.line([(107, 54), (53, 107)], fill="white", width=13)
    draw.ellipse((111, 15, 150, 54), fill="#e87932", outline="#fcfdfd", width=5)
    target = Path(__file__).resolve().parents[1] / "dashboard/assets/sentinelx.png"
    target.parent.mkdir(parents=True, exist_ok=True)
    image.save(target)


if __name__ == "__main__":
    main()