'''
Created on Apr 10, 2012

@organization: cert.org
'''

import unittest
import certfuzz.helpers as helpers
import platform
import string
import itertools

class Test(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_quoted(self):
        for s in list('qwertyuiopasdfghjklzxcvbnm'):
            self.assertTrue(s in helpers.quoted(s))
            self.assertEqual('"' + s + '"', helpers.quoted(s))


    def test_random_str(self):
        self.assertEqual(1, len(helpers.random_str()))
        random_string = helpers.random_str(100)
        self.assertEqual(100, len(random_string))
        for c in random_string:
            chars = string.ascii_letters + string.digits
            self.assertTrue(c in chars)

    def test_bitswap(self):
        for x, y in itertools.izip([0, 1, 2, 3, 4], [0, 128, 64, 192, 32]):
            self.assertEqual(y, helpers.bitswap(x))

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
