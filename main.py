import argparse
from getpass import getpass

from cryptography.exceptions import InvalidSignature

from crypto_agile.agility import encipher, decipher, VERSION_CLASSES


def encrypt(version, key, input_file, output_file):
    result = encipher(key=key,
                      plain_text_stream=input_file,
                      version_number=version)
    output_file.write(result)


def decrypt(key, input_file, output_file):
    result = decipher(key=key, cipher_text_stream=input_file)
    output_file.write(result)


if __name__ == '__main__':
    VERSIONS = VERSION_CLASSES.keys()
    parser = argparse.ArgumentParser(description='A crypto agile app which can encrypt a files.')
    parser.add_argument('action', choices=['encrypt', 'decrypt'])
    parser.add_argument('input_file', type=argparse.FileType('rb'))
    parser.add_argument('output_file', type=argparse.FileType('wb'))
    parser.add_argument('-V', '--algorithm_version', type=int, choices=VERSIONS, default=VERSIONS[0])
    parser.add_argument('--key')

    args = parser.parse_args()

    if not args.key:
        args.key = getpass('encryption key or password ?:')

    if args.action == 'encrypt':
        encrypt(args.algorithm_version, args.key, args.input_file, args.output_file)
    elif args.action == 'decrypt':
        try:
            decrypt(args.key, args.input_file, args.output_file)
        except ValueError as e:
            print "wrong password or corrupted file"
            print e
        except InvalidSignature as e:
            print "corrupted file"
            print e
