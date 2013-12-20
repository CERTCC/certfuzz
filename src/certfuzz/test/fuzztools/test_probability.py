'''
Created on Apr 8, 2011

@organization: cert.org
'''
from certfuzz.fuzztools.probability import FuzzRun
import math
from certfuzz.fuzztools.probability import lnfactorial
from certfuzz.fuzztools.probability import shot_size
from certfuzz.fuzztools.probability import misses_until_quit
import unittest

class Test(unittest.TestCase):

    def setUp(self):
        N = 52  # cards in the deck
        M = 4  # how many aces
        p = 5.0 / 52  # how many cards in a hand?
        self.fuzzrun = FuzzRun(N, M, p)

    def test_P_hit(self):
        self.assertAlmostEqual(self.fuzzrun.P_hit(), (1.0 / 54145))

    def test_P_miss(self):
        self.assertAlmostEqual(self.fuzzrun.P_miss(), (1 - (1.0 / 54145)))

    def test_ln_P(self):
        self.assertAlmostEqual(self.fuzzrun.ln_P(), math.log(1.0 / 54145))

    def test_lnfactorial(self):
        for x in range(1, 100):
            self.assertAlmostEqual(lnfactorial(x), math.log(math.factorial(x)))

    def test_shot_size(self):
        for N in range(5, 100000, 1000):
            for inv_p in range(2, 10002, 100):
                p = 1.0 / inv_p
                if (p * N > 1):
                    self.assertEqual(shot_size(N, p), int(math.floor(N * p)))

    def test_misses_until_quit(self):
        confidence = 0.5
        self.assertEqual(misses_until_quit(confidence, (1.0 / 54145)), 37531)

    def test_how_many_misses_until_quit(self):
        confidence = 0.5
        answer = int(math.ceil(math.log(1 - confidence) / math.log(1 - (1.0 / 54145))))
        self.assertEqual(self.fuzzrun.how_many_misses_until_quit(confidence), answer)

        # make sure we reject out-of-range values
        # 0.0 < confidence < 1.0
        self.assertRaises(AssertionError, self.fuzzrun.how_many_misses_until_quit, 1)
        self.assertRaises(AssertionError, self.fuzzrun.how_many_misses_until_quit, 0)

    def test_init(self):
        # N < M
        self.assertRaises(AssertionError, FuzzRun, 5, 10, 0.1)
        # 0.0 < p < 1.0
        self.assertRaises(AssertionError, FuzzRun, 52, 4, 0.0)
        self.assertRaises(AssertionError, FuzzRun, 52, 4, 1.0)

    def test_should_I_stop_yet(self):
        should_be_false = self.fuzzrun.how_many_misses_until_quit(0.5)
        for x in range(should_be_false):
            self.assertFalse(self.fuzzrun.should_I_stop_yet(x, 0.5))
        for x in range(should_be_false + 1, should_be_false + 1000):
            self.assertTrue(self.fuzzrun.should_I_stop_yet(x, 0.5))

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
