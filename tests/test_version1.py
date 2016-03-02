import unittest

from crypto_agile.versions.versions import Version1


class TestVersion1(unittest.TestCase):
    def test_simple(self):
        version1 = Version1()
        original_plain_text = "Some Message"
        key = "some key"
        cipher_dict = version1.encipher(
            key,
            original_plain_text
        )
        plain_text = version1.decipher(
            key=key,
            cipher_text=cipher_dict['cipher_text'],
            initialization_vector=cipher_dict['initialization_vector'],
            salt=cipher_dict['salt']
        )
        print cipher_dict
        print plain_text
        self.assertEqual(original_plain_text, plain_text)
