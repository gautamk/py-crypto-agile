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

    __metaclass__ = abc.ABCMeta

    @abstractmethod
    def generate_kdf(self, salt):
        pass

    @abstractmethod
    def generate_cipher(self, key, initialization_vector, salt):
        pass

    @abstractmethod
    def encipher(self, key, message):
        pass
