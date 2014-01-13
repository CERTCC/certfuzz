'''
Created on Feb 22, 2013

@organization: cert.org
'''
import unittest
from certfuzz.scoring.multiarmed_bandit.bayesian_bandit import BayesianMultiArmedBandit


class Test(unittest.TestCase):

    def setUp(self):
        self.mab = BayesianMultiArmedBandit()
        self.arms = 'abcdefghijklmnopqrstuvwxyz'
        for arm in self.arms:
            self.mab.add_item(arm, arm)

    def tearDown(self):
        pass

    def test_next(self):
        i = 1
        n = 1000
        limit = n * len(self.arms)
        from collections import defaultdict
        seen = defaultdict(int)
        for arm in self.mab:
            if i > limit:
                break
            seen[arm] += 1
            i += 1

        for arm in self.arms:
            # ensure we saw each arm about n times
            share = seen[arm] / float(n)
            self.assertLessEqual(0.9, share)
            self.assertGreaterEqual(1.1, share)

    def test_iter(self):
        self.assertIs(self.mab, self.mab.__iter__())

    def test_score(self):
        for key in 'abcdefghijklmnopqrstuvwxy':
            arm = self.mab.arms[key]
            self.assertEqual(0.5, arm.probability)
            arm.update(successes=0, trials=198)
            self.assertEqual(0.005, arm.probability)
        # we haven't touched z yet, so it should be fairly
        # high probability
        zarm = self.mab.arms['z']
        self.assertEqual(0.5, zarm.probability)
        scaled = self.mab._scaled_scores()
        self.assertEqual(0.8, scaled['z'])
        for key in 'abcdefghijklmnopqrstuvwxy':
            arm = self.mab.arms[key]
            self.assertEqual(0.005, arm.probability)
            self.assertEqual(0.008, scaled[key])
        # go ahead and pull z
        zarm.update(successes=0, trials=198)
        scaled = self.mab._scaled_scores()
        for key in self.arms:
            # now they should all be equal again
            arm = self.mab.arms[key]
            self.assertEqual(0.005, arm.probability)
            self.assertAlmostEqual(1.0 / len(self.arms), scaled[key], 6)

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
