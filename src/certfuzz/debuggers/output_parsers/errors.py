'''
Created on Oct 24, 2012

@organization: cert.org
'''
from certfuzz.debuggers.errors import DebuggerError


class DebuggerFileError(DebuggerError, IOError):
    pass


class UnknownDebuggerError(DebuggerError):
    pass
