'''
Created on Apr 12, 2013

@organization: cert.org
'''
from .. import CERTFuzzError

class TestCaseError(CERTFuzzError):
    pass

class CrashError(TestCaseError):
    pass

class AndroidTestCaseError(TestCaseError):
    pass
