'''
Created on Jan 10, 2014

@author: adh
'''
from ..errors import CERTFuzzError


class FuzztoolError(CERTFuzzError):
    pass


class DistanceMatrixError(FuzztoolError):
    pass


class RangeFinderError(Exception):
    pass


class SimilarityMatrixError(Exception):
    pass
