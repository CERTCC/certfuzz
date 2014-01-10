'''
Created on Apr 10, 2012

@organization: cert.org
'''
import unittest
import certfuzz.analyzers
from certfuzz.test import misc


class Test(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_api(self):
        module = certfuzz.analyzers
        api_list = ['Analyzer']
        (is_fail, msg) = misc.check_for_apis(module, api_list)
        self.assertFalse(is_fail, msg)


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
