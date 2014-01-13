'''
Created on Feb 22, 2013

@organization: cert.org
'''
import unittest
from certfuzz.scoring.multiarmed_bandit.random_bandit import RandomMultiArmedBandit


class Test(unittest.TestCase):

    def setUp(self):
        self.mab = RandomMultiArmedBandit()

    def tearDown(self):
        pass

    def test_next(self):
        arms = 'abcdefghijklmnopqrstuvwxyz'
        for arm in arms:
            self.mab.add_item(arm, arm)

        i = 1
        n = 10000
        limit = n * len(arms)
        from collections import defaultdict
        seen = defaultdict(int)
        for arm in self.mab:
            if i > limit:
                break
            seen[arm] += 1
            i += 1

        for arm in arms:
            # ensure we saw each arm about n times
            share = seen[arm] / float(n)
            self.assertAlmostEqual(1.0, share, 1)

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
