'''
Created on Apr 8, 2011

@organization: cert.org
'''
import unittest
from certfuzz.fuzztools.range import Range


class Test(unittest.TestCase):

    def setUp(self):
        self.r = Range(0, 1)

    def tearDown(self):
        pass

    def test_init(self):
        self.assertEqual(self.r.max, 1.0)
        self.assertEqual(self.r.min, 0.0)
        self.assertEqual(self.r.mean, 0.5)
        self.assertEqual(self.r.span, 1.0)

    def test_repr(self):
        self.assertEqual(self.r.__repr__(), '0.000000-1.000000')

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
