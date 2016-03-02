import struct

LITTLE_ENDIAN_UNSIGNED_INT = '<I'


def int_to_bytes(integer):
    return struct.pack(LITTLE_ENDIAN_UNSIGNED_INT, integer)


def bytes_to_int(byte_value):
    return struct.unpack(LITTLE_ENDIAN_UNSIGNED_INT, byte_value)[0]
