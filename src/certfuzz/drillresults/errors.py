'''
Created on Jul 1, 2014

@author: adh
'''
from certfuzz.tools.errors import CERTFuzzToolError


class DrillResultsError(CERTFuzzToolError):
    pass


class TestCaseBundleError(DrillResultsError):
    pass
