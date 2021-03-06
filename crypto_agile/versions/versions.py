from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES, TripleDES
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf import pbkdf2

from crypto_agile.constants import BITS_256_IN_BYTES, BITS_192_IN_BYTES
from crypto_agile.versions.version_spec import VersionSpec


class Version1(VersionSpec):
    VERSION_NUMBER = 1
    ITERATIONS = 100000
    BACKEND = default_backend()
    ALGORITHM = AES
    MODE = modes.CBC
    BLOCK_SIZE_IN_BITS = ALGORITHM.block_size
    BLOCK_SIZE_IN_BYTES = BLOCK_SIZE_IN_BITS / 8
    KEY_SIZE = BITS_256_IN_BYTES
    KDF = pbkdf2.PBKDF2HMAC
    HASH = hashes.SHA256
    PADDING = padding.PKCS7(BLOCK_SIZE_IN_BITS)
    MAC = HMAC


class Version2(VersionSpec):
    VERSION_NUMBER = 2
    ITERATIONS = 100000
    BACKEND = default_backend()
    ALGORITHM = TripleDES
    MODE = modes.CBC
    BLOCK_SIZE_IN_BITS = ALGORITHM.block_size
    BLOCK_SIZE_IN_BYTES = BLOCK_SIZE_IN_BITS / 8
    KEY_SIZE = BITS_192_IN_BYTES
    KDF = pbkdf2.PBKDF2HMAC
    HASH = hashes.SHA256
    PADDING = padding.PKCS7(BLOCK_SIZE_IN_BITS)
    MAC = HMAC
