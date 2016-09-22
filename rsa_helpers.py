#!/usr/bin/env python
# -*- coding: utf-8 -*-

import math
from random import randrange as randrange_insecure
from random import SystemRandom
from collections import namedtuple

randrange = SystemRandom().randrange

PrivateKey = namedtuple('PrivateKey', ('p', 'q', 'n', 'd'))
PublicKey = namedtuple('PublicKey', ('n', 'e'))

small_primes = [
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
    157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
    239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
    331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419,
    421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
    509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607,
    613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
    709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811,
    821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911,
    919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997
]


def rabin_miller(num, rounds):
    """Test if num is likely prime with rounds rounds of Rabin Miller
    """
    if num < 2 or num & 1 == 0:
        return False

    for prime in small_primes:
        if num < prime * prime:
            return True
        if num % prime == 0:
            return False

    r, s = 0, num - 1
    while s & 1 == 0:
        r += 1
        s //= 2

    for _ in range(rounds):
        a = randrange_insecure(2, num - 1)
        x = pow(a, s, num)
        if x == 1 or x == num - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, num)
            if x == num - 1:
                break
        else:
            return False
    return True


def prime_generate(bits, rb_rounds=10):
    """Generate a prime number with bits bits
    """
    rounds = int(100 * (math.log(bits, 2) + 1))
    for _ in range(rounds):
        canidate = randrange(1 << (bits - 1), 1 << bits)
        if rabin_miller(canidate, rb_rounds):
            return canidate
    return None


def gcd(a, b):
    """Uses Euler's Methods to determine the GCD of two numbers
    """
    while b != 0:
        a, b = b, a % b
    return a


def xgcd(b, n):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while n != 0:
        q, b, n = b // n, n, b % n
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return b, x0, y0


def multiplicative_inverse(a, n):
    """Extended Euclidian Algorithm to find x where a * x == 1 mod n
    """
    g, x, _ = xgcd(a, n)
    if g == 1:
        return x % n


def cp_encode(keybits, msg):
    """Chunk, pad - Encode Side
    """
    chunk_size = int(math.ceil(keybits / 8))
    msg_len = len(msg)
    chunks = []
    for i in range(0, msg_len, chunk_size):
        chunks.append(msg[i:i+chunk_size])
    chunks[-1] = chunks[-1] + (b'\x00' * (chunk_size - len(chunks[-1])))
    return [int.from_bytes(x, byteorder='big') for x in chunks]


def cp_decode(keybits, chunks):
    """Undo CP encoding
    """
    chunk_size = int(math.ceil(keybits / 8))
    msg = bytes()
    for chunk in chunks:
        msg += chunk.to_bytes(chunk_size, byteorder='big')
    return msg
