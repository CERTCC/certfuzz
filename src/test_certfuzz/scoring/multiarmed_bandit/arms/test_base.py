'''
Created on Feb 22, 2013

@organization: cert.org
'''
import unittest
from certfuzz.scoring.multiarmed_bandit.arms import base

class Test(unittest.TestCase):

    def setUp(self):
        self.arm = base.BanditArmBase()
        self.assertEqual(0, self.arm.successes)
        self.assertEqual(0, self.arm.trials)


    def tearDown(self):
        pass

    def test_init(self):
        self.assertEqual(0, self.arm.trials)
        self.assertEqual(0, self.arm.successes)
        self.assertEqual(1.0, self.arm.probability)

    def test_failures(self):
        for x in range(0, 10):
            for y in range(x, 10):
                self.arm.successes = x
                self.arm.trials = y
                self.assertEqual(y - x, self.arm.failures)

    def test_doubt(self):
        for x in range(1, 100, 5):
            for y in range(1, 100, 5):
                self.arm.successes = x
                self.arm.trials = x * y
                self.assertEqual(x, self.arm.successes)
                self.assertEqual(x * y, self.arm.trials)
                self.arm.doubt()
                self.assertEqual(1, self.arm.successes)
                self.assertEqual(y, self.arm.trials)

    def test_forget(self):
        self.arm.successes = 10
        self.arm.trials = 100
        self.assertEqual(10, self.arm.successes)
        self.assertEqual(100, self.arm.trials)
        self.arm.forget()
        self.assertEqual(0, self.arm.successes)
        self.assertEqual(0, self.arm.trials)

    def test_update(self):
        self.arm.update(successes=80, trials=800)
        self.assertEqual(80, self.arm.successes)
        self.assertEqual(800, self.arm.trials)

        self.arm.update(5, 10)
        self.assertEqual(85, self.arm.successes)
        self.assertEqual(810, self.arm.trials)


if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
