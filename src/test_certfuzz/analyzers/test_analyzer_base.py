'''
Created on Aug 8, 2011

@organization: cert.org
'''

import unittest
from certfuzz.analyzers.analyzer_base import Analyzer
from test_certfuzz.mocks import MockCfg, MockCrash



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
