# py-crypto-agile
An python cli to demonstrate crypto agility

# Introduction

> Cryptographic agility is the capacity for an IT system to easily evolve and adopt alternatives 
> to the cryptographic primitives it was originally designed to use.

source: http://crypto.stackexchange.com/a/31041/28190

# Requirements

- Python 2.7
- Cryptography.io (https://cryptography.io/en/latest/) (check requirements.txt for exact version)

# Implementation
Cryptoagility in this app is primarily built into the header. 
The file header specifies information on the encryption algorithm, key derivation function, hashing algorithm etc.
**All crypto primitives are from Cryptography.io** .

## File format

![](https://www.lucidchart.com/publicSegments/view/6f5a5901-beee-4580-99bc-c9d9710ef0a3/image.jpeg)


## Version Spec

### version number = 1
        VERSION_NUMBER = 1
        ITERATIONS = 100000
        ALGORITHM = AES
        MODE = modes.CBC
        BLOCK_SIZE = 128 bits
        KEY_SIZE = 256 bits
        KDF = PBKDF2_HMAC
        HASH = SHA256
        PADDING = PKCS7
        HMAC = SHA256-HMAC

### version number = 2
        VERSION_NUMBER = 2
        ITERATIONS = 100000
        ALGORITHM = 3DES
        MODE = modes.CBC
        BLOCK_SIZE = 64 bits
        KEY_SIZE = 192 bits
        KDF = PBKDF2_HMAC
        HASH = SHA256
        PADDING = PKCS7
        HMAC = SHA256-HMAC


## Key Generation

    key_master = KDF(password_from_user,
                        algorithm=version_spec.HASH,
                        length=version_spec.KEY_SIZE,
                        salt=salt_from_header,
                        iterations=version_spec.ITERATIONS)

    key_encrypt =  KDF(key_master,
                        algorithm=version_spec.HASH,
                        length=version_spec.KEY_SIZE,
                        salt='SALT_ENCRYPT',
                        iterations=version_spec.ITERATIONS)
    
    key_hmac =  KDF(key_master,
                        algorithm=version_spec.HASH,
                        length=version_spec.KEY_SIZE,
                        salt='SALT_HMAC',
                        iterations=version_spec.ITERATIONS)

## HMAC Generation / Verification

    
    hmac( key_hmac, concat( initialization_vector, cipher_text, msg_len ) , version_spec.HASH)