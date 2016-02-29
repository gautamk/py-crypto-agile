import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.kdf import pbkdf2

from crypto_agile.constants import BITS_256_IN_BYTES
from crypto_agile.version_spec import VersionSpec


class Version1(VersionSpec):
    ITERATIONS = 100000
    BACKEND = default_backend()
    BLOCK_SIZE = AES.block_size / 8
    ALGORITHM = AES
    MODE = modes.CBC
    KDF = pbkdf2.PBKDF2HMAC
    HASH = hashes.SHA256
    PADDING = padding.PKCS7(AES.block_size)
    """
        - AES-256-CBC
        - PKCS7
        - PBKDF2_HMAC
            - PKCS#5
            - SHA256
            - Input_password
            - salt(length=256bits)
            - 100,000 rounds
    """

    def generate_cipher(self, key, salt):
        kdf = self.generate_kdf(salt)
        secure_key = kdf.derive(key)
        initialization_vector = os.urandom(self.BLOCK_SIZE)
        return initialization_vector, Cipher(
            algorithm=self.ALGORITHM(secure_key),
            mode=self.MODE(initialization_vector),
            backend=self.BACKEND)

    def generate_kdf(self, salt):
        return self.KDF(
            algorithm=self.HASH(),
            length=BITS_256_IN_BYTES,
            salt=salt,
            iterations=self.ITERATIONS,
            backend=self.BACKEND)

    def encipher(self, key, message):
        super(Version1, self).encipher(key, message)
        salt = os.urandom(BITS_256_IN_BYTES)
        initialization_vector, cipher = self.generate_cipher(key, salt)
        encryptor = cipher.encryptor()
        padder = self.PADDING.padder()
        padded_message = padder.update(message) + padder.finalize()
        cipher_text = encryptor.update(padded_message) + encryptor.finalize()
        return {
            "salt": salt,
            "initialization_vector": initialization_vector,
            "cipher_text": cipher_text
        }
