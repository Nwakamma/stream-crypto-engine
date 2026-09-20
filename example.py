import io
from stream_crypto_engine import ZeroDiskFileCipher

cipher = ZeroDiskFileCipher(password="MySecurePassword123!")

# Simple test stream
data_stream = io.BytesIO(b"Hello world! Streaming encryption works.")
encrypted_buffer = io.BytesIO()

for frame in cipher.encrypt_stream(data_stream):
    encrypted_buffer.write(frame)

print(f"Encrypted size: {encrypted_buffer.tell()} bytes")