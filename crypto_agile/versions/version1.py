import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf import pbkdf2

from crypto_agile.constants import BITS_256_IN_BYTES
from crypto_agile.util import int_to_bytes
from crypto_agile.versions.version_spec import VersionSpec


class Version1(VersionSpec):
    VERSION_NUMBER = 1
    ITERATIONS = 100000
    BACKEND = default_backend()
    BLOCK_SIZE_IN_BITS = AES.block_size
    BLOCK_SIZE_IN_BYTES = BLOCK_SIZE_IN_BITS / 8
    ALGORITHM = AES
    MODE = modes.CBC
    KDF = pbkdf2.PBKDF2HMAC
    HASH = hashes.SHA256
    PADDING = padding.PKCS7(BLOCK_SIZE_IN_BITS)
    MAC = HMAC
    """
        - AES-256-CBC
        - PKCS7 Padding
        - PBKDF2_HMAC
            - PKCS#5
            - SHA256
            - Input_password
            - salt(length=256bits)
            - 100,000 rounds
    """

    def verify_hmac(self, signature, key_hmac, initialization_vector, cipher_text, msg_len):
        hmac = self.MAC(key_hmac, self.HASH(), self.BACKEND)
        hmac.update(initialization_vector)
        hmac.update(cipher_text)
        hmac.update(int_to_bytes(msg_len))
        return hmac.verify(signature)

    def generate_hmac(self, key_hmac, initialization_vector, cipher_text, msg_len):
        hmac = self.MAC(key_hmac, self.HASH(), self.BACKEND)
        hmac.update(initialization_vector)
        hmac.update(cipher_text)
        hmac.update(int_to_bytes(msg_len))
        return hmac.finalize()

    def generate_cipher(self, key, initialization_vector, salt):
        return Cipher(
            algorithm=self.ALGORITHM(key),
            mode=self.MODE(initialization_vector),
            backend=self.BACKEND)

    def _generate_secure_key(self, key, salt):
        kdf = self.KDF(
            algorithm=self.HASH(),
            length=BITS_256_IN_BYTES,
            salt=salt,
            iterations=self.ITERATIONS,
            backend=self.BACKEND)
        return kdf.derive(key)

    def generate_secure_keys(self, key, salt):
        key_master = self._generate_secure_key(key, salt)
        key_encrypt = self._generate_secure_key(key_master, self.SALT_ENCRYPT)
        key_hmac = self._generate_secure_key(key_master, self.SALT_HMAC)
        return key_master, key_encrypt, key_hmac

    def encipher(self, key, message):
        super(Version1, self).encipher(key, message)
        salt = os.urandom(BITS_256_IN_BYTES)
        initialization_vector = os.urandom(self.BLOCK_SIZE_IN_BYTES)
        key_master, key_encrypt, key_hmac = self.generate_secure_keys(key, salt)

        cipher = self.generate_cipher(key_encrypt, initialization_vector, salt)
        encryptor = cipher.encryptor()
        padder = self.PADDING.padder()
        padded_message = padder.update(message) + padder.finalize()
        cipher_text = encryptor.update(padded_message) + encryptor.finalize()

        msg_len = len(cipher_text)
        hmac = self.generate_hmac(key_hmac, initialization_vector, cipher_text, msg_len)

        return {
            'salt': salt,
            'initialization_vector': initialization_vector,
            'cipher_text': cipher_text,
            'hmac': hmac,
            'msg_len': msg_len
        }

    def decipher(self, key, cipher_text, salt, signature, initialization_vector, msg_len):
        key_master, key_encrypt, key_hmac = self.generate_secure_keys(key, salt)

        cipher = self.generate_cipher(key_encrypt, initialization_vector, salt)
        decryptor = cipher.decryptor()
        plain_text = decryptor.update(cipher_text) + decryptor.finalize()
        unpadder = self.PADDING.unpadder()
        unpadded_data = unpadder.update(plain_text) + unpadder.finalize()

        self.verify_hmac(signature, key_hmac, initialization_vector, cipher_text, msg_len)
        return unpadded_data
