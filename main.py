from crypto_agile.agility import encipher, decipher

FILE = "/tmp/temp_cipher.txt"

with open(FILE, 'wb') as f:
    encipher(key="somekey", message="somemessage", stream_object=f)

with open(FILE, 'rb') as f:
    decipher("somekey", f, None)
