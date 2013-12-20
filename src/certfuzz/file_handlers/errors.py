'''
Created on Apr 12, 2013

@organization: cert.org
'''
from .. import CERTFuzzError

class FileHandlerError(CERTFuzzError):
    pass

class BasicFileError(FileHandlerError):
    pass

class FuzzedFileError(BasicFileError):
    pass

class SeedFileError(BasicFileError):
    pass
