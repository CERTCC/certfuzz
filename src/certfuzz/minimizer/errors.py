'''
Created on Jul 9, 2013

@organization: cert.org
'''
from certfuzz.errors import CERTFuzzError


class MinimizerError(CERTFuzzError):
    pass


class WindowsMinimizerError(MinimizerError):
    pass
