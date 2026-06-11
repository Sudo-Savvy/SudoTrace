import base64
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# In-memory key store — cleared on Docker restart, cleared on logout
_session_keys: dict[str, bytes] = {}


# PBKDF2-HMAC-SHA256 work factor. 600k matches current OWASP guidance.
# NOTE: changing this value changes every derived key, so credentials
# encrypted under an older count become undecryptable — callers must
# treat a decrypt failure as "not configured" (see credentials router)
# so the analyst simply re-enters them once.
_PBKDF2_ITERATIONS = 600_000


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode())


def store_key(session_id: str, key: bytes) -> None:
    _session_keys[session_id] = key


def get_key(session_id: str) -> bytes | None:
    return _session_keys.get(session_id)


def clear_key(session_id: str) -> None:
    _session_keys.pop(session_id, None)


def encrypt_field(plaintext: str, key: bytes) -> str:
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ciphertext).decode()


def decrypt_field(ciphertext_b64: str, key: bytes) -> str:
    data = base64.b64decode(ciphertext_b64)
    nonce, ciphertext = data[:12], data[12:]
    return AESGCM(key).decrypt(nonce, ciphertext, None).decode()
