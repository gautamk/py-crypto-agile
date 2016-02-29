import unittest

from crypto_agile.version1 import Version1


class TestVersion1(unittest.TestCase):
    def test_simple(self):
        version1 = Version1()
        print version1.encipher(
            "some_key",
            "some_message"
        )
        self.fail()
