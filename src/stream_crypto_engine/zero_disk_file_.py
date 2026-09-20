from pathlib import Path
from typing import Generator, Tuple
from io import BytesIO
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
import io, os, struct
from magic import magic




class ZeroDiskFileCipher:
    """
        In-memory file inspection, streaming encryption, and decryption engine.
        Ensures unencrypted payloads never touch server disk storage.
        """
    CHUNK_SIZE = 64 * 1024  # 64 KB streaming buffer
    def __init__(self, password: str = None):
        self.password = password

    def initialize(self, password: str):
        if not password:
            raise ValueError("Password is required.")
        self.password = password


    def _derive_key(self, salt: bytes) -> bytes:
        """Derives a 256-bit key from password using Argon2id."""
        if not self.password:
            raise ValueError("Password is required.")
        key = Argon2id(
            salt=salt,
            lanes=4,
            iterations=3,
            length=32,
            memory_cost=65536
        )

        return key.derive(self.password.encode("utf-8"))

    def detect_file_type(self, sample_bytes: bytes) -> str:
        """
        Inspects the first few bytes (magic numbers) to determine file type/MIME.
        Does not rely on file extensions.
        """
        mime = magic.Magic(mime=True)
        detected_type = mime.from_buffer(sample_bytes)
        return detected_type or "application/octet-stream"

    def encrypt_stream(self, input_stream: io.BufferedIOBase) -> Generator[bytes, None, Tuple[str, int]]:
        """
                Reads input stream, detects MIME type from initial bytes, encrypts in memory chunks,
                and yields binary frames directly without writing to disk.
        """

        # 1. Read first chunk to inspect magic bytes and detect file type
        first_chunk = input_stream.read(self.CHUNK_SIZE)
        if not first_chunk:
            raise ValueError("Cannot encrypt an empty stream.")

        detected_mime = self.detect_file_type(first_chunk)
        mime_bytes = detected_mime.encode("utf-8")

        # 2. Prepare Encryption Parameters
        salt = os.urandom(16)
        nonce_prefix = os.urandom(8)
        key = self._derive_key(salt)
        aesgcm = AESGCM(key)

        # 3. Header Frame:
        # [ Salt (16B) | Nonce Prefix (8B) | Chunk Size (4B) | MIME Len (2B) | MIME Bytes ]
        header = (
                salt
                + nonce_prefix
                + struct.pack(">I", self.CHUNK_SIZE)
                + struct.pack(">H", len(mime_bytes))
                + mime_bytes
        )
        yield header

        chunk_counter = 0

        # Helper function to process individual chunk payload
        def process_chunk(raw_chunk: bytes, counter: int) -> bytes:
            nonce = nonce_prefix + struct.pack(">I", counter)
            encrypted = aesgcm.encrypt(nonce, raw_chunk, None)
            return struct.pack(">I", len(encrypted)) + encrypted

        # Encrypt the initial sample chunk
        yield process_chunk(first_chunk, chunk_counter)
        chunk_counter += 1

        # Stream and encrypt remaining chunks
        while True:
            chunk = input_stream.read(self.CHUNK_SIZE)
            if not chunk:
                break
            yield process_chunk(chunk, chunk_counter)
            chunk_counter += 1

        return detected_mime, chunk_counter

    def decrypt_stream(
            self, encrypted_stream: io.BufferedIOBase
    ) -> Generator[bytes, None, str]:
        """
        Reads encrypted stream from memory, recovers MIME type from header,
        verifies authenticity tags, and yields original plaintext chunks.
        """
        # 1. Parse Header
        salt = encrypted_stream.read(16)
        nonce_prefix = encrypted_stream.read(8)
        chunk_size_bytes = encrypted_stream.read(4)
        mime_len_bytes = encrypted_stream.read(2)

        if len(salt) < 16 or len(nonce_prefix) < 8 or len(chunk_size_bytes) < 4 or len(mime_len_bytes) < 2:
            raise ValueError("Corrupted or invalid encrypted stream format.")

        mime_len = struct.unpack(">H", mime_len_bytes)[0]
        detected_mime = encrypted_stream.read(mime_len).decode("utf-8")

        key = self._derive_key(salt)
        aesgcm = AESGCM(key)

        chunk_counter = 0

        # 2. Decrypt Sequential Chunks
        while True:
            length_bytes = encrypted_stream.read(4)
            if not length_bytes:
                break

            chunk_len = struct.unpack(">I", length_bytes)[0]
            encrypted_chunk = encrypted_stream.read(chunk_len)

            if len(encrypted_chunk) != chunk_len:
                raise ValueError("Truncated or damaged ciphertext payload.")

            nonce = nonce_prefix + struct.pack(">I", chunk_counter)

            try:
                decrypted_chunk = aesgcm.decrypt(nonce, encrypted_chunk, None)
                yield decrypted_chunk
            except InvalidTag:
                raise ValueError("Decryption failed: Incorrect password or tampered ciphertext.")

            chunk_counter += 1

        return detected_mime

    def handle_file_encryption(self, input_file_path: Path):
        """
        Pass the file absolute path for encryption
        :param input_file_path:
        :return:
        """

        if not self.password:
            raise ValueError("Password is required.")
        file_byte = input_file_path.read_bytes()

        # Wrap in in-memory stream buffer
        incoming_raw_stream = io.BytesIO(file_byte)
        encrypted_memory_buffer = io.BytesIO()

        # Pass through encryption generator
        for encrypted_frame in self.encrypt_stream(incoming_raw_stream):
            encrypted_memory_buffer.write(encrypted_frame)


        return encrypted_memory_buffer

    def handle_file_decryption(self, encrypted_memory_buffer: BytesIO):
        # -------------------------------------------------------------
        # 2. STREAM DECRYPTION IN RAM
        # -------------------------------------------------------------
        encrypted_memory_buffer.seek(0)  # Reset buffer position to start

        decrypted_memory_buffer = io.BytesIO()

        # Create decryptor generator
        decrypt_gen = self.decrypt_stream(encrypted_memory_buffer)

        try:
            for plaintext_chunk in decrypt_gen:
                decrypted_memory_buffer.write(plaintext_chunk)
        except Exception as e:
            print("Decryption Error:", e)

        restored_data = decrypted_memory_buffer.getvalue()

        exists = bool(restored_data)
        return decrypted_memory_buffer, exists