import abc
import os

from cryptography.hazmat.primitives.ciphers import Cipher

from crypto_agile.util import int_to_bytes


class VersionSpec(object):
    VERSION_NUMBER = None
    ITERATIONS = None
    BACKEND = None
    BLOCK_SIZE_IN_BITS = None
    BLOCK_SIZE_IN_BYTES = None
    KEY_SIZE = None
    ALGORITHM = None
    MODE = None
    KDF = None
    HASH = None
    PADDING = None
    MAC = None
    SALT_HMAC = "SALT_HMAC"
    SALT_ENCRYPT = "SALT_ENCRYPT"

    __metaclass__ = abc.ABCMeta

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

    def generate_cipher(self, key, initialization_vector):
        return Cipher(
            algorithm=self.ALGORITHM(key),
            mode=self.MODE(initialization_vector),
            backend=self.BACKEND)

    def _generate_secure_key(self, key, salt):
        kdf = self.KDF(
            algorithm=self.HASH(),
            length=self.KEY_SIZE,
            salt=salt,
            iterations=self.ITERATIONS,
            backend=self.BACKEND)
        return kdf.derive(key)

    def generate_secure_keys(self, key, salt):
        key_master = self._generate_secure_key(key, salt)
        key_encrypt = self._generate_secure_key(key_master, self.SALT_ENCRYPT)
        key_hmac = self._generate_secure_key(key_master, self.SALT_HMAC)
        return key_master, key_encrypt, key_hmac

    def pad_data(self, plain_text):
        padder = self.PADDING.padder()
        padded_message = padder.update(plain_text) + padder.finalize()
        return padded_message

    def encipher(self, key, plain_text):
        salt = os.urandom(self.KEY_SIZE)
        initialization_vector = os.urandom(self.BLOCK_SIZE_IN_BYTES)
        key_master, key_encrypt, key_hmac = self.generate_secure_keys(key, salt)

        cipher = self.generate_cipher(key_encrypt, initialization_vector)
        encryptor = cipher.encryptor()
        padded_message = self.pad_data(plain_text)
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

    def unpad_data(self, plain_text):
        unpadder = self.PADDING.unpadder()
        unpadded_data = unpadder.update(plain_text) + unpadder.finalize()
        return unpadded_data

    def decipher(self, key, cipher_text, salt, signature, initialization_vector, msg_len):
        key_master, key_encrypt, key_hmac = self.generate_secure_keys(key, salt)

        cipher = self.generate_cipher(key_encrypt, initialization_vector)
        decryptor = cipher.decryptor()
        plain_text = decryptor.update(cipher_text) + decryptor.finalize()
        unpadded_data = self.unpad_data(plain_text)

        self.verify_hmac(signature, key_hmac, initialization_vector, cipher_text, msg_len)
        return unpadded_data
