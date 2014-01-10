'''
Created on Jan 10, 2014

@author: adh
'''
from ..errors import CERTFuzzError


class AnalyzerError(CERTFuzzError):
    pass


class AnalyzerOutputMissingError(AnalyzerError):
    '''
    Exception class for missing output files
    '''
    def __init__(self, f):
        self.file = f

    def __str__(self):
        return "Expected output file is missing: %s" % self.file


class AnalyzerEmptyOutputError(AnalyzerError):
    '''
    Exception class for missing output files
    '''
    def __init__(self, f):
        self.file = f

    def __str__(self):
        return "Output file is empty: %s" % self.file
