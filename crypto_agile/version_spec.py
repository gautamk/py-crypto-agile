import abc
from abc import abstractmethod


class VersionSpec(object):
    __metaclass__ = abc.ABCMeta

    @abstractmethod
    def generate_kdf(self, salt):
        pass

    @abstractmethod
    def generate_cipher(self, key, salt):
        pass

    @abstractmethod
    def encipher(self, key, message):
        pass
