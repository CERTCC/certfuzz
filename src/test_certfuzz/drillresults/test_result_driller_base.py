'''
Created on Jul 2, 2014

@organization: cert.org
'''
import unittest
import certfuzz.drillresults.result_driller_base
from certfuzz.drillresults.result_driller_base import ResultDriller

alphabet = 'abcdefghijklmnopqrstuvwxyz'


class MockRd(ResultDriller):
    # really_exploitable expects a list
    really_exploitable = list(alphabet)

    def _parse_testcase(self):
        pass

    def _platform_find_testcases(self):
        pass

    def check_64bit(self):
        pass


class Test(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_rd_acts_as_metaclass(self):
        self.assertRaises(TypeError, ResultDriller)

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
