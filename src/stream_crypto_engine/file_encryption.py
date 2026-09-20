import os
import struct
import io
from typing import Generator
from typing import BinaryIO
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id


class ModulaFileStreamEncryption:
    CHUNK_SIZE = 64 * 1024  # 64 KB read/write buffer

    def __init__(self, password: str):
        if not password:
            raise ValueError("A valid password is required for stream encryption.")
        self.password = password

    def _derive_key(self, salt: bytes) -> bytes:
        """Derives a 256-bit AES key from the user's password using Argon2id."""
        kdf = Argon2id(
            salt=salt,
            length=32,
            lanes=2,
            memory_cost=65536,  # 64 MB memory cost
            iterations=1,
        )
        return kdf.derive(self.password.encode("utf-8"))

    def encrypt_stream(self, input_stream: BinaryIO, output_stream: BinaryIO) -> None:
        """
        Reads plaintext from input_stream in chunks and writes encrypted payloads to output_stream.
        """
        # 1. Header setup: 16B Salt + 8B Nonce Prefix + 4B Chunk Size
        salt = os.urandom(16)
        nonce_prefix = os.urandom(8)
        key = self._derive_key(salt)
        aesgcm = AESGCM(key)

        output_stream.write(salt)
        output_stream.write(nonce_prefix)
        output_stream.write(struct.pack(">I", self.CHUNK_SIZE))

        chunk_counter = 0

        # 2. Read in fixed-size chunks from disk/stream
        while True:
            chunk = input_stream.read(self.CHUNK_SIZE)
            if not chunk:
                break  # End of file reached

            # Nonce construction: 8B prefix + 4B big-endian chunk counter
            nonce = nonce_prefix + struct.pack(">I", chunk_counter)

            # Encrypt chunk (AESGCM appends 16-byte authentication tag)
            encrypted_chunk = aesgcm.encrypt(nonce, chunk, None)

            # Frame writing: 4B chunk length header + encrypted chunk data
            output_stream.write(struct.pack(">I", len(encrypted_chunk)))
            output_stream.write(encrypted_chunk)

            chunk_counter += 1

    def decrypt_stream(self, input_stream: BinaryIO, output_stream: BinaryIO) -> None:
        """
        Reads encrypted chunks from input_stream, verifies authenticity, and writes plaintext to output_stream.
        """
        # 1. Parse header metadata
        salt = input_stream.read(16)
        nonce_prefix = input_stream.read(8)
        chunk_size_bytes = input_stream.read(4)

        if len(salt) < 16 or len(nonce_prefix) < 8 or len(chunk_size_bytes) < 4:
            raise ValueError("Invalid stream format: Corrupted or truncated header.")

        key = self._derive_key(salt)
        aesgcm = AESGCM(key)

        chunk_counter = 0

        # 2. Read chunk framing and decrypt sequentially
        while True:
            length_bytes = input_stream.read(4)
            if not length_bytes:
                break  # Reached end of stream cleanly

            chunk_len = struct.unpack(">I", length_bytes)[0]
            encrypted_chunk = input_stream.read(chunk_len)

            if len(encrypted_chunk) != chunk_len:
                raise ValueError("Unexpected end of stream or truncated chunk payload.")

            # Reconstruct unique nonce for chunk index
            nonce = nonce_prefix + struct.pack(">I", chunk_counter)

            # Decrypt payload and verify authentication tag (raises InvalidTag on mismatch/tampering)
            decrypted_chunk = aesgcm.decrypt(nonce, encrypted_chunk, None)

            # Write clean plaintext out to disk stream
            output_stream.write(decrypted_chunk)
            chunk_counter += 1

    # Convenient file path helpers
    def encrypt_file(self, input_path: str, output_path: str) -> None:
        with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
            self.encrypt_stream(fin, fout)

    def decrypt_file(self, input_path: str, output_path: str) -> None:
        with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
            self.decrypt_stream(fin, fout)

    def encrypt_stream_generator(
            self,
            file_obj: io.BufferedIOBase, chunk_size: int = 64 * 1024
    ) -> Generator[bytes, None, None]:
        """Reads unencrypted chunks from upload stream and yields encrypted payload frames."""
        salt = os.urandom(16)
        nonce_prefix = os.urandom(8)
        key = self._derive_key(salt)
        aesgcm = AESGCM(key)

        # Yield binary header frame: Salt (16B) + Nonce Prefix (8B) + Chunk Size (4B)
        yield salt + nonce_prefix + struct.pack(">I", chunk_size)

        chunk_counter = 0
        while True:
            chunk = file_obj.read(chunk_size)
            if not chunk:
                break

            nonce = nonce_prefix + struct.pack(">I", chunk_counter)
            encrypted_chunk = aesgcm.encrypt(nonce, chunk, None)

            # Yield frame: 4-byte payload length header + encrypted chunk payload
            yield struct.pack(">I", len(encrypted_chunk)) + encrypted_chunk
            chunk_counter += 1