from crypto_agile.agility import encipher, decipher

INPUT_FILE = '/home/gautam/Pictures/Selection_006.png'
OUTPUT_CIPHER_TEXT = "/tmp/cipher_text"
OUTPUT_PLAIN_TEXT = '/tmp/plain_text'
KEY = "somekey"

with open(INPUT_FILE, 'rb') as f:
    result = encipher(KEY, plain_text_stream=f)

with open(OUTPUT_CIPHER_TEXT, 'wb') as f:
    f.write(result)

with open(OUTPUT_CIPHER_TEXT, 'rb') as f:
    result = decipher(KEY, f)

with open(OUTPUT_PLAIN_TEXT, 'wb') as f:
    f.write(result)
