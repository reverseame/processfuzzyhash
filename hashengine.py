import string
import ssdeep
import fuzzyhashlib
import re
import tlsh
import dcfldd

class HashEngine(object):
    def __init__(self, algorithm, strings=False):
        super(HashEngine, self).__init__()
        self.engine = self.resolve_engine(algorithm.lower())
        self.strings = strings

    def resolve_engine(self, algorithm):
        if algorithm == 'ssdeep':
            return SSDeep()
        elif algorithm == 'sdhash':
            return SDHash()
        elif algorithm == 'tlsh':
            return TLSH()
        elif algorithm == 'dcfldd':
            return Dcfldd()

        raise InvalidAlgorithm('Invalid fuzzy hash algorithm')

    def get_algorithm(self):
        return self.engine.get_algorithm()

    def calculate(self, file=None, data=None):
        if file:
            with open(file) as f:
                data = f.read()

        if self.strings:
            """Get all ASCII strings from binary data"""
            data = '\n'.join(get_strings(data))

        return self.engine.calculate(data)

    def compare(self, hash1, hash2):
        return self.engine.compare(hash1, hash2)

class SSDeep(object):
    def __init__(self):
        super(SSDeep, self).__init__()
    
    def get_algorithm(self):
        return 'SSDeep'

    def calculate(self, data):
        return ssdeep.hash(data)

    def compare(self, hash1, hash2):
        try:
            return ssdeep.compare(hash1, hash2)
        except ssdeep.InternalError, reason:
            return 'Error: {0}'.format(reason)

class SDHash(object):
    def __init__(self):
        super(SDHash, self).__init__()

    def get_algorithm(self):
        return 'SDHash'

    def calculate(self, data):
        try:
            return fuzzyhashlib.sdhash(data).hexdigest().strip()
        except ValueError, reason:
            return 'Error: {0} ({1:d})'.format(reason, len(data))

    def compare(self, hash1, hash2):
        if re.search(r'^Error:', hash1) or re.search(r'^Error:', hash2):
            return '0'

        # Bad hash comparation
        return fuzzyhashlib.sdhash(hash=hash1) - fuzzyhashlib.sdhash(hash=hash2)

class TLSH(object):
    def __init__(self):
        super(TLSH, self).__init__()
    
    def get_algorithm(self):
        return 'TLSH'

    def calculate(self, data):
        if len(data) < 50:
            return 'Error: TLSH requires buffer >= 50 in size ({0:d})'.format(len(data))

        fingerprint = tlsh.hash(data)

        return fingerprint if fingerprint else 'Error: empty hash'

    def compare(self, hash1, hash2):
        return tlsh.diffxlen(hash1, hash2)

class Dcfldd(object):
    def __init__(self):
        super(Dcfldd, self).__init__()
    
    def get_algorithm(self):
        return 'dcfldd'

    def calculate(self, data):
        try:
            return dcfldd.hash(data, 100, dcfldd.MD5)
        except dcfldd.InvalidDcflddHashFunc, reason:
            return 'Error: {0}'.format(reason)

    def compare(self, hash1, hash2):
        try:
            return dcfldd.compare(str(hash1), str(hash2))
        except dcfldd.InvalidDcflddComparison, reason:
            return 'Error: {0}'.format(reason)

class InvalidAlgorithm(Exception):
    pass

def get_strings(data, min=4):
    """
    Get all strings of a given data

    @param data: binary data
    @param min: minimum string length

    @returns a generator with all strings
    """
    stream = ''

    for char in data:
        if char in string.printable:
            stream += char
            continue
        if len(stream) >= min:
            yield stream
        stream = ''
    # Catch result at EOF
    if len(stream) >= min:
        yield stream
