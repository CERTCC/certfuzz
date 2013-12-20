'''
Created on Aug 8, 2011

@organization: cert.org
'''

import unittest
from certfuzz.analyzers import Analyzer

class MockObj(object):
    def __init__(self, **kwargs):
        for (kw, arg) in kwargs:
            self.__setattr__(kw, arg)

class MockCfg(MockObj):

    def get_command_list(self, *args):
        pass

class MockCrash(MockObj):
    def __init__(self):
        self.fuzzedfile = MockFile()
        self.killprocname = 'killprocname'

class MockFile(MockObj):
    def __init__(self):
        self.dirname = 'dirname'
        self.path = 'path'

class Test(unittest.TestCase):

    def setUp(self):
        cfg = MockCfg()
        crash = MockCrash()
        self.analyzer = Analyzer(cfg, crash, timeout=0)
        self.assertTrue(self.analyzer, 'Analyzer does not exist')

    def tearDown(self):
        pass

    def testName(self):
        pass

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
