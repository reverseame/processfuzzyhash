'''
    File name: dcfldd.py
    Author: Inaki Abadia
    Date created: 2017/01/02
    Date last modified: 2018/04/22 by Daniel Uroz
    Python Version: 2.7
'''

#from __future__ import division
import hashlib
import math
import sys

MD5, SHA1, SHA256, CTPH = range(4)

def hash(data, blocks, hash_f):
    dcfldd_hash = ''
    # Data length
    bs = math.ceil(len(data) / float(blocks))
    bs = int(bs)

    # hash function
    if hash_f == MD5:
        hash_func = hashlib.md5
        dcfldd_hash = 'md5:'
    elif hash_f == SHA1:
        hash_func = hashlib.sha1
        dcfldd_hash = 'sha1:'
    elif hash_f == SHA256:
        hash_func = hashlib.sha256
        dcfldd_hash = 'sha256:'
    else:
        raise InvalidDcflddHashFunc('\'{0}\' is not a valid dcfldd hash function.'.format(hash_f))

    # hash
    try:
        hash_array = [hash_func(data[i:i+bs]).hexdigest() for i in range(0, len(data), bs)]
        # fill hash until 'blocks' elements
        for i in range(len(hash_array), blocks):
            hash_array.append(hash_func("\0"*bs).hexdigest())

        # Build hash str
        for h in hash_array:
            dcfldd_hash += h + ':'
        return dcfldd_hash[:-1]
    except ValueError as e:
        sys.stderr.write('Error: Data length: {0}'.format(len(data)))

    return '-'

def compare(h1, h2):
    score = 0
    h1_array = h1.split(':')
    h2_array = h2.split(':')

    if not h1_array[0] == h2_array[0]:
        raise InvalidDcflddComparison('\'{0}\' - \'{1}\': Can not compare different hash functions'.format(h1_array[0], h2_array[0]))

    if len(h1_array) != len(h2_array):
        raise InvalidDcflddComparison('Can not compare different hash size: h1_size: \'{0}\' h2_size: \'{1}\' '.format(len(h1_array), len(h2_array)))

    for i in range(1, len(h1_array)):
        if h1_array[i] == h2_array[i]:
            score = score + 1
    return score

class InvalidDcflddHashFunc(Exception):
    pass

class InvalidDcflddComparison(Exception):
    pass
