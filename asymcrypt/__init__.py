# -*- coding: utf-8 -*-
'''
Created : 2018-09-18

@author: Eric Lapouyade
'''

__version__ = '0.0.2'

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP


def generate_keys(private_key_file='private_key.pem',
                  public_key_file='public_key.pem',
                  passphrase=None):
    """Generate private/public keys files

    Args:
        private_key_file (str): the file path for the private key
        public_key_file (str): the file path for the public key
        passphrase (str): The passphrase to crypt keys (optional)

    Returns:
        str: encrypted data
    """
    key = RSA.generate(2048)
    private_key = key.export_key(passphrase=passphrase, pkcs=8,
                              protection="scryptAndAES128-CBC")
    with open(private_key_file, "wb") as file_out:
        file_out.write(private_key)

    public_key = key.publickey().export_key(passphrase=passphrase, pkcs=8,
                              protection="scryptAndAES128-CBC")
    with open(public_key_file, "wb") as file_out:
        file_out.write(public_key)


def encrypt_data(data, public_key_file='public_key.pem', passphrase=None):
    """Encrypt data

    Args:
        data (str or unicode): the data to be encrypted
        public_key_file (str): the file path for the public key
        passphrase (str): The passphrase used when generating keys (optional)

    Returns:
        str: encrypted data

    Note:
        If data is unicode, it will be 'utf-8' encoded
    """

    # read public key
    recipient_key = RSA.import_key(open(public_key_file).read(), passphrase)
    session_key = get_random_bytes(16)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    output = enc_session_key + cipher_aes.nonce + tag + ciphertext

    return output


def decrypt_data(data, private_key_file='private_key.pem', passphrase=None):
    """Decrypt a file with given private key file

    Args:
        data (str): the data to be decrypted
        private_key_file (str): the file path for the private key
        passphrase (str): The passphrase used when generating keys (optional)

    Returns:
        str: decrypted data (utf-8 encoded if encrypted as unicode)
    """

    # read private key
    private_key = RSA.import_key(open(private_key_file).read(), passphrase)

    pksize = private_key.size_in_bytes()
    enc_session_key = data[:pksize]
    nonce = data[pksize:pksize + 16]
    tag = data[pksize + 16:pksize + 32]
    ciphertext = data[pksize + 32:]

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    output = cipher_aes.decrypt_and_verify(ciphertext, tag)

    return output
