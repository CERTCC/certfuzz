'''
Created on Oct 23, 2012

@organization: cert.org
'''
from certfuzz.errors import CERTFuzzError


class FuzzerError(CERTFuzzError):
    pass


# raise this exception if your fuzzer is out of ways to manipulate
# the seed file
class FuzzerExhaustedError(FuzzerError):
    pass


class FuzzerInputMatchesOutputError(FuzzerError):
    pass
