import requests
import mimetypes, secrets
from pathlib import Path
from urllib.parse import urlparse
from io import BytesIO


def download_file(url: str, save_dir: str = ".", filename: str | None = None) -> Path:
    """
    Download a file and automatically detect the correct extension.

    Priority:
    1. Content-Type header
    2. Extension from URL
    3. Magic bytes (first chunk) as last resort
    """
    save_dir = Path(save_dir)
    save_dir.mkdir(parents=True, exist_ok=True)

    with requests.get(url, stream=True) as response:
        response.raise_for_status()

        # --- 1. Try Content-Type header ---
        content_type = response.headers.get("Content-Type", "").split(";")[0].strip().lower()
        ext = mimetypes.guess_extension(content_type)

        # --- 2. Fallback: extension from URL ---
        if not ext:
            path = urlparse(url).path
            ext = Path(path).suffix or None

        # --- 3. Fallback: magic bytes from first chunk ---
        first_chunk = next(response.iter_content(chunk_size=8192), b"")
        if not ext and first_chunk:
            ext = _guess_ext_from_magic(first_chunk)

        # Final fallback
        if not ext:
            ext = ".bin"

        # Build filename
        if filename is None:
            base_name = Path(urlparse(url).path).stem or "downloaded_file"
            filename = f"{base_name}{ext}"
        else:
            # If user provided a name without extension, add the detected one
            if not Path(filename).suffix:
                filename = f"{filename}{ext}"

        save_path = save_dir / filename

        # Write the file (first chunk + rest)
        with open(save_path, "wb") as f:
            if first_chunk:
                f.write(first_chunk)
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)

    print(f"Downloaded → {save_path}")
    return save_path


def _guess_ext_from_magic(data: bytes) -> str | None:
    """Very basic magic-byte detection for common types"""
    if data.startswith(b"%PDF"):
        return ".pdf"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if data.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if data[4:8] == b"ftyp":  # MP4 / MOV / etc.
        return ".mp4"
    if data.startswith(b"GIF8"):
        return ".gif"
    if data.startswith(b"PK\x03\x04"):
        return ".zip"
    if data.startswith(b"\x1f\x8b"):
        return ".gz"
    return None

def generate_secrets(length = 32):
    return secrets.token_urlsafe(length)


def path_to_bytesio(file_path: Path) -> BytesIO:
    """Reads a file from a Path object and loads it into a BytesIO stream."""
    # 1. Read all binary data from the file path
    file_bytes = file_path.read_bytes()

    # 2. Load the bytes into an in-memory BytesIO stream
    bytes_io_stream = BytesIO(file_bytes)

    return bytes_io_stream