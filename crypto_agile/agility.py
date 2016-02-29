import struct

from crypto_agile.versions.version1 import Version1

LITTLE_ENDIAN_UNSIGNED_INT = '<I'

VERSION_CLASSES = {
    1: Version1
}


def generate_header():
    pass


def encipher(key, message, stream_object, version_class=Version1):
    version = version_class()
    salt, initialization_vector, cipher_text = version.encipher(key, message)
    msg_len = len(cipher_text)

    # 4bytes
    stream_object.write(struct.pack(LITTLE_ENDIAN_UNSIGNED_INT, version.VERSION_NUMBER))
    # 32 bytes
    stream_object.write(salt)
    # 16 bytes
    stream_object.write(initialization_vector)
    # 4 bytes
    stream_object.write(struct.pack(LITTLE_ENDIAN_UNSIGNED_INT, msg_len))
    stream_object.write(cipher_text)


def decipher(key, input_stream, stream_object):
    version_number = struct.unpack(LITTLE_ENDIAN_UNSIGNED_INT, input_stream.read(4))[0]
    version_class = VERSION_CLASSES[version_number]
    version = version_class()

    salt = input_stream.read(32)
    initialization_vector = input_stream.read(16)
    msg_len = struct.unpack(LITTLE_ENDIAN_UNSIGNED_INT, input_stream.read(4))[0]
    cipher_text = input_stream.read(msg_len)

    print version.decipher(key, cipher_text, salt, initialization_vector)
