=========
asymcrypt
=========

Super easy asymmetric encryption for python

Introduction
------------

python-asymcrypt is a wrapper around pycryptodome to make it even more easier
for asymmetric encryption.

Installation
------------

With pip ::

    pip install asymcrypt


Usage
-----

Generate keys files ::

    import asymcrypt

    asymcrypt.generate_keys('my_private_key_file.pem','my_public_key_file.pem')

Encrypt data ::

    data = 'A string, not an unicode'
    encrypted_data = asymcrypt.encrypt_data(data,'my_public_key_file.pem')

Decrypt data ::

    data = asymcrypt.decrypt_data(encrypted_data,'my_private_key_file.pem')


Passphrase
----------

As an option, you can use ``passphrase`` option in each functions to generate encrypted keys
and read them when using encrypt/decrypt_data() functions

Command line
------------

Asymcrypt provides 3 commands :

To generate keys pair ::

    asymgenkeys -priv private_key.pem -pub public_key.pem

To encrypt ::

    asymencrypt -k public_key.pem -in file_to_encrypt.txt -out dest_file.enc

To decrypt ::

    asymdecrypt -k private_key.pem -in encrypted_file.enc -out dest_file.txt

Note :  you may use option ``-b`` or ``--base64`` to encode/decode in base64
and ``-p`` or  ``--passphrase`` to specify a passphrase to encrypt/decrypt keys
