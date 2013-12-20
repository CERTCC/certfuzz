'''
Created on Oct 23, 2012

@organization: cert.org
'''


class DebuggerError(Exception):
    pass


class UndefinedDebuggerError(DebuggerError):
    '''
    Exception class for undefined debuggers
    '''
    def __init__(self, system):
        self.system = system

    def __str__(self):
        return "No debugger defined for '%s'" % self.system


class DebuggerNotFoundError(DebuggerError):
    def __init__(self, debugger):
        self.debugger = debugger

    def __str__(self):
        return "Could not find debugger '%s' in path" % self.debugger
