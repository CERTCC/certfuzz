'''
Created on Oct 24, 2012

@organization: cert.org
'''
class DebuggerError(Exception):
    pass
class DebuggerFileError(DebuggerError, IOError):
    pass
class UnknownDebuggerError(DebuggerError):
    pass
