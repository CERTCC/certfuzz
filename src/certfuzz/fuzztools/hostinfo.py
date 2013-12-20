'''
Created on Jul 15, 2011

@organization: cert.org
'''
import platform
#from .. import debuggers

system = platform.system()

class HostInfoError(Exception):
    pass

class UnsupportedPlatformError(HostInfoError):
    def __init__(self, system):
        self.system = system
    def __str__(self):
        return "'%s' is not a supported platform." % self.system

class HostInfo(object):
    def __init__(self):
        '''
        Constructor
        '''
        self.verify()

    def is_windows(self):
        return (system == "Windows")

    def is_osx(self):
        return (system == "Darwin")

    def is_linux(self):
        return (system == "Linux")

    def verify(self):
        # add other tests here
        pass
