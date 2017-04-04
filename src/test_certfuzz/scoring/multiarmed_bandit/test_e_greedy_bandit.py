'''
Created on Jan 8, 2014

@author: adh
'''
from certfuzz.scoring.multiarmed_bandit.e_greedy_bandit import EpsilonGreedyMultiArmedBandit
from certfuzz.scoring.multiarmed_bandit.errors import MultiArmedBanditError
import math
import unittest


class Test(unittest.TestCase):

    def setUp(self):
        self.mab = EpsilonGreedyMultiArmedBandit()
        self.keys = 'abcd'
        self._add_things()

    def tearDown(self):
        pass

    def _add_things(self):
        for v, k in enumerate(self.keys):
            self.mab.add_item(k, v)

    def _bump_p(self, k):
        # bump p(k) up half the distance to the goal
        p_orig = self.mab.arms[k].probability

        inv_p = 1.0 - p_orig
        half_inv_p = 0.5 * inv_p
        p_new = p_orig + half_inv_p

        self.mab.arms[k].probability = p_new

    def test_init_raises_err(self):
        self.assertRaises(MultiArmedBanditError, EpsilonGreedyMultiArmedBandit, epsilon=1.00001)
        self.assertRaises(MultiArmedBanditError, EpsilonGreedyMultiArmedBandit, epsilon=-0.0001)

    def test_max_key(self):
        mab = self.mab
        self._bump_p('a')
        self.assertTrue('a' in mab._max_keys())

        self._bump_p('b')
        # now both a and be should be max
        seen = set()
        for _i in range(20):
            ks = mab._max_keys()
            for k in ks:
                seen.add(k)
        # There is a very small probability that this could fail
        # but it's analogous to flipping heads 20x in a row.
        # You can always bump up the iteration count in the above for loop
        # if you want to reduce the probability of failure here
        self.assertTrue('a' in seen)
        self.assertTrue('b' in seen)

    def test_all_except(self):
        mab = self.mab
        self._bump_p('a')

        self.assertFalse('a' in mab._all_except('a'))
        for k in self.keys[1:]:
            self.assertTrue(k in mab._all_except('a'))

    def test__iter__(self):
        # iterator should return itself
        self.assertEqual(self.mab, self.mab.__iter__())

    def test_next_key(self):
        mab = self.mab
        mab.e = 0.1
        self._bump_p('a')

        counters = {}
        for _k in self.keys:
            counters[_k] = 0

        N = 10000
        for _i in range(N):
            k = mab._next_key()
            counters[k] += 1

        # expect 9k 'a's if N=10k
        self.assertAlmostEqual(1 - mab.e, counters['a'] / float(N), 1)
        other_counts = N - counters['a']
        other_keys = mab._all_except('a')
        n_others = len(other_keys)
        for x in other_keys:
            actual = counters[x]
            expected = float(other_counts) / n_others
            ratio = actual / expected
            err = math.fabs(ratio - 1.0)
            tolerance = 0.2
            # I haven't done the math to figure out the probability of this failing,
            # but it should be fairly small. In my initial checks the err was typically <0.1
            self.assertLessEqual(err, tolerance)

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
