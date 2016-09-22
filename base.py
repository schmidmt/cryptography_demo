#!/usr/bin/env python
# -*- coding: utf-8 -*-


class EncrypterDecrypterBase:

    def __init__(self, key):

        if hasattr(key, 'read'):
            if key.mode != 'rb':
                raise ValueError('File stream must be mode readable and binary')
            self.key = key.read()
        elif isinstance(key, bytes):
            self.key = key
        elif isinstance(key, str):
            self.key = bytes(key)
        else:
            raise ValueError('Key must be a file, string, or bytes')
