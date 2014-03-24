'''
Created on Feb 22, 2013

@organization: cert.org
'''
import unittest
from certfuzz.scoring.multiarmed_bandit.arms.bayes_laplace import BanditArmBayesLaplace


class Test(unittest.TestCase):

    def setUp(self):
        self.arm = BanditArmBayesLaplace()

    def tearDown(self):
        pass

    def test_update_p(self):
        self.assertEqual(0, self.arm.trials)
        self.assertEqual(0, self.arm.successes)
        self.assertEqual(1.0 / 2.0, self.arm.probability)
        self.arm.update(1, 1)
        self.assertEqual(2.0 / 3.0, self.arm.probability)
        self.arm.update(1, 1)
        self.assertEqual(3.0 / 4.0, self.arm.probability)
        self.arm.successes = 0
        self.assertEqual(2, self.arm.trials)
        self.arm._update_p()
        self.assertEqual(0.25, self.arm.probability)

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
