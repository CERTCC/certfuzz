from certfuzz.fuzztools.seedrange import MAX_SEED
from certfuzz.fuzztools.seedrange import SEED_INTERVAL
from certfuzz.fuzztools.seedrange import SeedRange

'''
Created on Apr 8, 2011

@organization: cert.org
'''
import unittest

class Test(unittest.TestCase):
    def setUp(self):
        self.seedrange = SeedRange(0, SEED_INTERVAL, MAX_SEED)

    def test_set_s2(self):
        sr = self.seedrange
        for i in range(0, 1000):
            sr.s1 = i
            sr.set_s2()
            self.assertEqual(sr.s2, i + SEED_INTERVAL)

    def test_increment_seed(self):
        sr = self.seedrange
        self.assertEqual(sr.s1, 0)
        sr.increment_seed()
        self.assertEqual(sr.s1, 1)

    def test_in_range(self):
        sr = self.seedrange
        self.assertTrue(sr.in_range())
        sr.s1 = sr.s2 - 1
        self.assertTrue(sr.in_range())
        sr.s1 += 1
        self.assertFalse(sr.in_range())

    def test_in_max_range(self):
        sr = self.seedrange
        self.assertTrue(sr.in_max_range())
        sr.s1 = sr.max_seed - 1
        self.assertTrue(sr.in_max_range())
        sr.s1 += 1
        self.assertFalse(sr.in_max_range())

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
