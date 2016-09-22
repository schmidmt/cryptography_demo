#!/usr/bin/env python
# -*- coding: utf-8 -*-

# import argparse
import rsa_helpers


def generate_key_pair(bits):
    """Make a set of RSA Keys of bits bits
    """
    bits_per_key = bits // 2
    prime_q = rsa_helpers.prime_generate(bits_per_key)
    prime_p = rsa_helpers.prime_generate(bits_per_key)

    n = prime_q * prime_p
    phi = (prime_q - 1) * (prime_p - 1)
    e = (1 << 16) + 1  # Must be relatively prime to phi
    d = rsa_helpers.multiplicative_inverse(e, phi)

    private = rsa_helpers.PrivateKey(p=prime_p,
                                     q=prime_q,
                                     n=n,
                                     d=d)

    public = rsa_helpers.PublicKey(n=n, e=e)

    check_keys(private, public)

    return private, public


def check_keys(priv, pub):
    phi = (priv.p - 1) * (priv.q - 1)
    d = priv.d
    e = pub.e

    assert((e * d) % phi == 1)
    assert(priv.p * priv.q == priv.n)
    assert(priv.p * priv.q == pub.n)


def encrypt(public_key, msg):
    """Encrypt a message with a public key
    """
    key_bits = public_key.n.bit_length()
    chunks = rsa_helpers.cp_encode(key_bits, msg)
    encoded_chunks = [pow(c, public_key.e, public_key.n) for c in chunks]
    return rsa_helpers.cp_decode(key_bits, encoded_chunks)


def decrypt(private_key, msg):
    """Decrypt a message with a private key
    """
    key_bits = private_key.n.bit_length()
    chunks = rsa_helpers.cp_encode(key_bits, msg)
    decoded_chunks = [pow(c, private_key.d, private_key.n) for c in chunks]
    return rsa_helpers.cp_decode(key_bits, decoded_chunks)
