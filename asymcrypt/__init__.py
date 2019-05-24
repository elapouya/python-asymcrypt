# -*- coding: utf-8 -*-
'''
Created : 2018-09-18

@author: Eric Lapouyade
'''

__version__ = '0.0.10'
__author__ = 'Eric Lapouyade'
__copyright__ = 'Copyright 2018, python-asymcrypt project'
__credits__ = ['Eric Lapouyade']
__license__ = 'LGPL'
__maintainer__ = 'Eric Lapouyade'
__status__ = 'Beta'

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import base64
import sys

keys_cache = {}


def get_key(key_file, passphrase=None):
    if key_file not in keys_cache:
        keys_cache[key_file] = RSA.import_key(open(key_file).read(), passphrase)
    return keys_cache[key_file]


def clear_cache_keys():
    global keys_cache
    keys_cache = {}


def clear_cache_key(key):
    global keys_cache
    if key in keys_cache:
        del keys_cache[key]


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
    if passphrase is not None:
        private_key = key.export_key(passphrase=passphrase, pkcs=8,
                                     protection="scryptAndAES128-CBC")
        public_key = key.publickey().export_key(passphrase=passphrase, pkcs=8,
                                                protection="scryptAndAES128-CBC")
    else:
        private_key = key.export_key()
        public_key = key.publickey().export_key()

    with open(private_key_file, "wb") as file_out:
        file_out.write(private_key)

    with open(public_key_file, "wb") as file_out:
        file_out.write(public_key)


def encrypt_data(data, public_key_file='public_key.pem', passphrase=None,
                 out_format='bin', in_encoding='utf-8'):
    """Encrypt data

    Args:
        data (str or unicode): the data to be encrypted
        public_key_file (str): the file path for the public key
        passphrase (str): The passphrase used when generating keys (optional)
        out_format (str): If 'base64' will encode into base64 after encryption
        in_encoding (str): if not bytes (py3) or string (py2),
                data will be encoded with that encoding (Default : utf-8)

    Returns:
        str: encrypted data

    Note:
        If data is unicode, it will be 'utf-8' encoded
    """

    # Check data type, encode to bytes(py3) or str(py2) if needed
    has_been_encoded = b'N'
    if ((sys.version_info.major == 2 and not isinstance(data, str)) or
        (sys.version_info.major >= 3 and isinstance(data, str))):
        data = data.encode(in_encoding)
        has_been_encoded = b'Y'

    # read public key
    recipient_key = get_key(public_key_file, passphrase)
    session_key = get_random_bytes(16)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    output = enc_session_key + cipher_aes.nonce + tag + has_been_encoded + ciphertext

    # Encode into base64 if requested
    if out_format == 'base64':
        output = base64.b64encode(output)

    return output


def decrypt_data(data, private_key_file='private_key.pem', passphrase=None,
                 in_format='bin', out_encoding='utf-8'):
    """Decrypt a file with given private key file

    Args:
        data (str): the data to be decrypted
        private_key_file (str): the file path for the private key
        passphrase (str): The passphrase used when generating keys (optional)
        in_format (str): If 'base64' will decode base64 before decrypting
        out_encoding (str): if original data before encryption has been encoded,
            decode it with specified encoding (Default : utf-8)

    Returns:
        decrypted data
    """

    # Decode from base64 if requested
    if in_format == 'base64':
        data = base64.b64decode(data)

    # read private key
    private_key = get_key(private_key_file, passphrase)

    pksize = private_key.size_in_bytes()
    enc_session_key = data[:pksize]
    nonce = data[pksize:pksize + 16]
    tag = data[pksize + 16:pksize + 32]
    has_been_encoded = data[pksize + 32:pksize + 33]
    ciphertext = data[pksize + 33:]

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    output = cipher_aes.decrypt_and_verify(ciphertext, tag)

    # decode output if it was encoded at encryption time
    if out_encoding and has_been_encoded == b'Y':
        output = output.decode(out_encoding)

    return output
