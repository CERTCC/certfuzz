'''
Created on Jul 15, 2011

@organization: cert.org
'''
import platform

system = platform.system()


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
