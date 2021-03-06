import StringIO

from crypto_agile.util import int_to_bytes, bytes_to_int
from crypto_agile.versions.versions import Version1, Version2

VERSION_CLASSES = {
    1: Version1,
    2: Version2
}


def generate_header():
    pass


def encipher(key, plain_text_stream, version_number=1):
    version_class = VERSION_CLASSES[version_number]
    version = version_class()
    cipher_dict = version.encipher(key, plain_text_stream.read())

    stream_object = StringIO.StringIO()

    # 4bytes
    stream_object.write(int_to_bytes(version.VERSION_NUMBER))
    # 4bytes
    stream_object.write(int_to_bytes(cipher_dict['msg_len']))

    # 32 bytes
    stream_object.write(cipher_dict['hmac'])

    # key_size of algorithm
    stream_object.write(cipher_dict['salt'])

    # block_size of algorithm
    stream_object.write(cipher_dict['initialization_vector'])

    stream_object.write(cipher_dict['cipher_text'])

    result = stream_object.getvalue()
    stream_object.close()
    return result


def decipher(key, cipher_text_stream):
    version_number = bytes_to_int(cipher_text_stream.read(4))
    version_class = VERSION_CLASSES[version_number]
    version = version_class()

    msg_len = bytes_to_int(cipher_text_stream.read(4))

    hmac_signature = cipher_text_stream.read(version_class.HASH.digest_size)

    salt = cipher_text_stream.read(version_class.KEY_SIZE)
    initialization_vector = cipher_text_stream.read(version_class.BLOCK_SIZE_IN_BYTES)

    cipher_text = cipher_text_stream.read(msg_len)

    return version.decipher(key=key,
                            cipher_text=cipher_text,
                            salt=salt, signature=hmac_signature,
                            initialization_vector=initialization_vector,
                            msg_len=msg_len)
