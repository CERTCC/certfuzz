'''
Created on Apr 10, 2012

@organization: cert.org
'''
import unittest
import certfuzz

class Test(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_api(self):
        self.assertTrue(hasattr(certfuzz, '__version__'))
        self.assertEqual(str, type(certfuzz.__version__))

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
