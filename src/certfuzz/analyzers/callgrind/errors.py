'''
Created on Oct 23, 2012

@organization: cert.org
'''
from ..errors import AnalyzerError


class CallgrindAnnotateError(AnalyzerError):
    pass


class CallgrindAnnotateMissingInputFileError(CallgrindAnnotateError):
    def __init__(self, f):
        self.file = f

    def __str__(self):
        return "Input file does not exist: %s" % self.file


class CallgrindAnnotateNoOutputFileError(CallgrindAnnotateError):
    def __init__(self, f):
        self.file = f

    def __str__(self):
        return "Output file does not exist: %s" % self.file


class CallgrindAnnotateEmptyOutputFileError(CallgrindAnnotateError):
    def __init__(self, f):
        self.file = f

    def __str__(self):
        return "Output file is empty: %s" % self.file
