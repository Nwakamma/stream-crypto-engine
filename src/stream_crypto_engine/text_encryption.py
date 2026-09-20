import os
import struct
from io import BytesIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id


class ModulaTextEncryption:
    CHUNK_SIZE = 64 * 1024  # 64 KB per chunk

    def __init__(self, text: str = None, password: str = None):
        self.text = text
        self.password = password


    def initialize(self, text: str, password: str):
        self.text = text
        self.password = password

    def check_text_size(self) -> int:
        return len(self.text.encode('utf-8'))

    def derive_key(self, salt: bytes) -> bytes:
        """Derives a 256-bit AES key from a password using Argon2id."""
        if not self.password:
            raise ValueError("A password or secret key must be provided.")

        kdf = Argon2id(
            salt=salt,
            length=32,
            memory_cost=65536,  # 64 MB RAM
            lanes= 4,
            iterations=3,
        )
        return kdf.derive(self.password.encode('utf-8'))

    def encrypt(self) -> bytes:

        if not self.text:
            raise ValueError("A text must be provided.")

        text_bytes = self.text.encode('utf-8')
        total_len = len(text_bytes)

        if total_len == 0:
            return b""

        # 1. Generate cryptographic salt and random 8-byte nonce prefix
        salt = os.urandom(16)
        nonce_prefix = os.urandom(8)  # 8 bytes base + 4 bytes counter = 12-byte GCM Nonce
        key = self.derive_key(salt)
        aesgcm = AESGCM(key)

        output = BytesIO()
        # Header: Salt (16B) + Nonce Prefix (8B) + Chunk Size Uint32 (4B)
        output.write(salt)
        output.write(nonce_prefix)
        output.write(struct.pack(">I", self.CHUNK_SIZE))

        # 2. Process in chunks
        chunk_counter = 0
        for i in range(0, total_len, self.CHUNK_SIZE):
            chunk = text_bytes[i: i + self.CHUNK_SIZE]

            # Construct a unique 12-byte nonce per chunk: prefix (8B) + counter (4B)
            nonce = nonce_prefix + struct.pack(">I", chunk_counter)

            # Encrypt chunk (AESGCM appends a 16-byte authentication tag)
            encrypted_chunk = aesgcm.encrypt(nonce, chunk, None)

            # Write chunk length header (4B) + encrypted chunk payload
            output.write(struct.pack(">I", len(encrypted_chunk)))
            output.write(encrypted_chunk)

            chunk_counter += 1

        return output.getvalue()

    @classmethod
    def decrypt(cls, encrypted_data: bytes, password: str) -> str:
        try:
            if not encrypted_data:
                return ""

            stream = BytesIO(encrypted_data)

            # 1. Read header
            salt = stream.read(16)
            nonce_prefix = stream.read(8)
            chunk_size = struct.unpack(">I", stream.read(4))[0]

            # 2. Derive key using Argon2id
            kdf = Argon2id(
                salt=salt,
                length=32,
                memory_cost=65536,
                lanes=4,
                iterations=3,
            )
            key = kdf.derive(password.encode('utf-8'))
            aesgcm = AESGCM(key)

            # 3. Decrypt chunks sequentially
            decrypted_bytes = bytearray()
            chunk_counter = 0

            while True:
                length_bytes = stream.read(4)
                if not length_bytes:
                    break  # End of stream

                chunk_len = struct.unpack(">I", length_bytes)[0]
                encrypted_chunk = stream.read(chunk_len)

                # Reconstruct unique nonce for this chunk sequence
                nonce = nonce_prefix + struct.pack(">I", chunk_counter)

                # Decrypt and verify AEAD authentication tag
                decrypted_chunk = aesgcm.decrypt(nonce, encrypted_chunk, None)
                decrypted_bytes.extend(decrypted_chunk)
                chunk_counter += 1

            return decrypted_bytes.decode('utf-8')
        except InvalidTag:
            raise ValueError(f"Decryption failed: Incorrect password or tampered ciphertext.")