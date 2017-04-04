'''
Created on Apr 10, 2012

@organization: cert.org
'''

import unittest
import certfuzz.helpers.misc as misc
import string
import itertools

class Test(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_fixup_path(self):
        path = '~/foo'
        self.assertTrue('~' not in misc.fixup_path(path))

    def test_quoted(self):
        for s in list('qwertyuiopasdfghjklzxcvbnm'):
            self.assertTrue(s in misc.quoted(s))
            self.assertEqual('"' + s + '"', misc.quoted(s))


    def test_random_str(self):
        self.assertEqual(1, len(misc.random_str()))
        random_string = misc.random_str(100)
        self.assertEqual(100, len(random_string))
        for c in random_string:
            chars = string.ascii_letters + string.digits
            self.assertTrue(c in chars)

    def test_bitswap(self):
        for x, y in zip([0, 1, 2, 3, 4], [0, 128, 64, 192, 32]):
            self.assertEqual(y, misc.bitswap(x))

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
