import StringIO
import struct

from crypto_agile.versions.version1 import Version1

LITTLE_ENDIAN_UNSIGNED_INT = '<I'

VERSION_CLASSES = {
    1: Version1
}


def generate_header():
    pass


def encipher(key, plain_text_stream, version_class=Version1):
    version = version_class()
    salt, initialization_vector, cipher_text = version.encipher(key, plain_text_stream.read())
    msg_len = len(cipher_text)

    stream_object = StringIO.StringIO()

    # 4bytes
    stream_object.write(struct.pack(LITTLE_ENDIAN_UNSIGNED_INT, version.VERSION_NUMBER))
    # 4 bytes
    stream_object.write(struct.pack(LITTLE_ENDIAN_UNSIGNED_INT, msg_len))

    # 32 bytes
    stream_object.write(salt)
    # 16 bytes
    stream_object.write(initialization_vector)

    stream_object.write(cipher_text)

    result = stream_object.getvalue()
    stream_object.close()
    return result


def decipher(key, cipher_text_stream):
    version_number = struct.unpack(LITTLE_ENDIAN_UNSIGNED_INT, cipher_text_stream.read(4))[0]
    version_class = VERSION_CLASSES[version_number]
    version = version_class()

    msg_len = struct.unpack(LITTLE_ENDIAN_UNSIGNED_INT, cipher_text_stream.read(4))[0]

    salt = cipher_text_stream.read(32)
    initialization_vector = cipher_text_stream.read(16)

    cipher_text = cipher_text_stream.read(msg_len)

    return version.decipher(key, cipher_text, salt, initialization_vector)
