"""QR image decoder with byte and decompressed-pixel limits.

Decoded payloads remain untrusted data; this module never opens links.
"""
from io import BytesIO
from typing import Optional

MAX_QR_IMAGE_PIXELS = 20_000_000
ALLOWED_FORMATS = {"PNG", "JPEG", "WEBP"}


def decode_qr_image(image_bytes: bytes) -> Optional[str]:
    if not image_bytes:
        return None
    try:
        # Verify dimensions and image container before OpenCV allocates pixel buffers.
        from PIL import Image, UnidentifiedImageError
        with Image.open(BytesIO(image_bytes)) as image:
            if image.format not in ALLOWED_FORMATS:
                return None
            width, height = image.size
            if width <= 0 or height <= 0 or width * height > MAX_QR_IMAGE_PIXELS:
                return None
            image.verify()
        # Re-open after verify(), which consumes the original PIL image stream.
        with Image.open(BytesIO(image_bytes)) as image:
            image.load()
            if image.width * image.height > MAX_QR_IMAGE_PIXELS:
                return None
        import cv2
        import numpy as np
        data = np.frombuffer(image_bytes, dtype=np.uint8)
        decoded_image = cv2.imdecode(data, cv2.IMREAD_COLOR)
        if decoded_image is None:
            return None
        if decoded_image.shape[0] * decoded_image.shape[1] > MAX_QR_IMAGE_PIXELS:
            return None
        detector = cv2.QRCodeDetector()
        value, _points, _straight = detector.detectAndDecode(decoded_image)
        return value.strip() if value and value.strip() else None
    except Exception:
        # Invalid/corrupt image data and missing optional dependencies fail closed.
        return None
