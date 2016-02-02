'''
Created on Jan 29, 2016

@author: adh
'''
import unittest
from certfuzz.analyzers import drillresults
from test_certfuzz.mocks import MockCfg, MockTestcase

class Test(unittest.TestCase):


    def setUp(self):
        cfg = MockCfg()
        testcase=MockTestcase()
        self.dra = drillresults.DrillResults(cfg,testcase)
        pass


    def tearDown(self):
        pass


    def testInit(self):
        self.assertTrue('debugger' in self.dra.cfg)
    
    def test_go(self):
        self.dra.go()


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()