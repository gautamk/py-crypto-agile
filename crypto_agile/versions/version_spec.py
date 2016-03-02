import abc
from abc import abstractmethod


class VersionSpec(object):
    VERSION_NUMBER = None
    ITERATIONS = None
    BACKEND = None
    BLOCK_SIZE_IN_BITS = None
    BLOCK_SIZE_IN_BYTES = None
    ALGORITHM = None
    MODE = None
    KDF = None
    HASH = None
    PADDING = None
    MAC = None
    SALT_HMAC = "SALT_HMAC"
    SALT_ENCRYPT = "SALT_ENCRYPT"

    __metaclass__ = abc.ABCMeta

    

    @abstractmethod
    def generate_hmac(self, key_hmac, initialization_vector, cipher_text, msg_len):
        pass

    @abstractmethod
    def verify_hmac(self, signature, key_hmac, initialization_vector, cipher_text, msg_len):
        pass

    @abstractmethod
    def generate_secure_keys(self, key, salt):
        pass

    @abstractmethod
    def generate_cipher(self, key, initialization_vector, salt):
        pass

    @abstractmethod
    def encipher(self, key, message):
        pass
