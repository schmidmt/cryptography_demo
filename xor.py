#!/usr/bin/env python
# -*- coding: utf-8 -*-

import binascii
from base import EncrypterDecrypterBase


class XOr(EncrypterDecrypterBase):
    """Encrypt/Decrypting data using XOr Cypher

    Arguments
    ---------
        key (bytes|File|string): Key for encryption
    """

    def encrypt(self, plain):
        """Encrypt a string or bytes
        """
        plain = bytearray(plain)
        key_len = len(self.key)
        env = bytes(c ^ self.key[i % key_len] for i, c in enumerate(plain))
        return env

    def decrypt(self, enc):
        """Decrypt encipher text
        """
        return self.encrypt(enc)


def main():
    """Demo of Encyption and Decryption
    """
    a = 'abc123'.encode('utf8')
    xor = XOr(b'hello')
    enc = xor.encrypt(a)
    dec = xor.decrypt(enc)
    print(a, binascii.hexlify(enc), dec)

if __name__ == "__main__":
    main()
