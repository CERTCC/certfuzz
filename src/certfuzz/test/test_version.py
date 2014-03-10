'''
Created on Feb 22, 2013

@organization: cert.org
'''
import unittest
from certfuzz import version


class Test(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def testName(self):
        self.assertTrue(hasattr(version, '__version__'), 'version has no attribute __version__')
        self.assertEqual(str, type(version.__version__))

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
