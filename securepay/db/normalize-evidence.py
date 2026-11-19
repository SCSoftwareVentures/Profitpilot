"""Sandbox JPEG decoder. Requires a separately provisioned, patched Pillow.
Read bounded stdin; emit only normalized RGB PNG; never retain originals."""
import io
import sys
import warnings
from PIL import Image, ImageFile, ImageOps

CAP = 2097152
Image.MAX_IMAGE_PIXELS = 4000000
ImageFile.LOAD_TRUNCATED_IMAGES = False
warnings.simplefilter("error", Image.DecompressionBombWarning)
try:
    raw = sys.stdin.buffer.read(CAP + 1)
    if not 8 <= len(raw) <= CAP or not raw.startswith(b"\xff\xd8\xff") or not raw.endswith(b"\xff\xd9"):
        raise ValueError("invalid JPEG")
    with Image.open(io.BytesIO(raw), formats=["JPEG"]) as im:
        if im.format != "JPEG" or not 0 < im.width <= 4096 or not 0 < im.height <= 4096 or im.width * im.height > 4000000:
            raise ValueError("dimensions")
        im.verify()
    with Image.open(io.BytesIO(raw), formats=["JPEG"]) as im:
        im.load()
        oriented = ImageOps.exif_transpose(im)
        rgb = oriented.convert("RGB")
        # Copy pixels alone. No metadata, color profile, comments or EXIF.
        output = Image.new("RGB", rgb.size)
        output.paste(rgb)
        encoded = io.BytesIO()
        output.save(encoded, format="PNG", compress_level=6)
        data = encoded.getvalue()
        if len(data) > CAP:
            raise ValueError("output exceeds cap")
        sys.stdout.buffer.write(data)
except Exception:
    sys.exit(2)
