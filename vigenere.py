#!/usr/bin/env python
# -*- coding: utf-8 -*-

import binascii
from base import EncrypterDecrypterBase


class Vigenere(EncrypterDecrypterBase):
    """Encrypt/Decrypting data using Vigenere Cypher

    Arguments
    ---------
        key (bytes|File|string): Key for encryption
    """

    def encrypt(self, plain):
        """Encrypt a string or bytes
        """
        plain = bytearray(plain)
        key_len = len(self.key)
        enc = bytes((c + self.key[i % key_len]) % 256 for i, c in enumerate(plain))
        return enc

    def decrypt(self, enc):
        """Decrypt encipher text
        """
        enc = bytearray(enc)
        key_len = len(self.key)
        plain = bytes((c - self.key[i % key_len]) % 256 for i, c in enumerate(enc))
        return plain


def main():
    """Demo of Encyption and Decryption
    """
    a = 'abc123'.encode('utf8')
    vig = Vigenere(b'hello')
    enc = vig.encrypt(a)
    dec = vig.decrypt(enc)
    print(a, binascii.hexlify(enc), dec)

if __name__ == "__main__":
    main()
