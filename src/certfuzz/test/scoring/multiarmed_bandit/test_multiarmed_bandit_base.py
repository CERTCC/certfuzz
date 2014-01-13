'''
Created on Feb 22, 2013

@organization: cert.org
'''
import unittest
from certfuzz.scoring.multiarmed_bandit.multiarmed_bandit_base import MultiArmedBanditBase
from certfuzz.scoring.multiarmed_bandit.errors import MultiArmedBanditError


class Test(unittest.TestCase):

    def setUp(self):
        self.mab = MultiArmedBanditBase()
        self.keys = 'abcdefghijklmnopqrstuvwxyz'
        for arm in self.keys:
            self.mab.add_item(arm, arm)

    def tearDown(self):
        pass

    def test_add(self):
        self.assertRaises(MultiArmedBanditError, self.mab.add_item)
        self.assertRaises(MultiArmedBanditError, self.mab.add_item, key=None, obj='obj')
        self.assertRaises(MultiArmedBanditError, self.mab.add_item, key='key', obj=None)

        self.assertEqual(len(self.keys), len(self.mab.things))
        self.assertEqual(len(self.keys), len(self.mab.arms))
        self.mab.add_item('foo', 'bar')
        self.assertEqual(len(self.keys) + 1, len(self.mab.things))
        self.assertEqual(len(self.keys) + 1, len(self.mab.arms))
        self.assertEqual(1.0, self.mab.arms['foo'].probability)

    def test_record_result(self):
        self.assertEqual(0, self.mab.successes)
        self.assertEqual(0, self.mab.trials)
        self.mab.record_result('a', 1, 10)
        self.assertEqual(1, self.mab.successes)
        self.assertEqual(10, self.mab.trials)
        self.mab.record_result('b', 11, 100)
        self.assertEqual(12, self.mab.successes)
        self.assertEqual(110, self.mab.trials)

        # make sure the arms are behaving as expected
        self.assertEqual(1, self.mab.arms['a'].successes)
        self.assertEqual(10, self.mab.arms['a'].trials)
        self.assertEqual(11, self.mab.arms['b'].successes)
        self.assertEqual(100, self.mab.arms['b'].trials)
        for x in 'cdefghijklmnopqrstuvwxyz':
            self.assertEqual(0, self.mab.arms[x].successes)
            self.assertEqual(0, self.mab.arms[x].trials)

    def test_trials(self):
        self.assertEqual(0, self.mab.trials)
        count = 0
        for arm in self.mab.arms.values():
            count += 1
            arm.update(trials=1)
            self.assertEqual(count, self.mab.trials)

    def test_successes(self):
        self.assertEqual(0, self.mab.successes)
        count = 0
        for arm in self.mab.arms.values():
            count += 1
            arm.update(successes=1)
            self.assertEqual(count, self.mab.successes)

    def test_total_p(self):
        total = sum(a.probability for a in self.mab.arms.values())
        self.assertEqual(total, self.mab._total_p)

        for a in self.mab.arms.itervalues():
            a.probability = a.probability * 0.5
        self.assertEqual(total * 0.5, self.mab._total_p)

    def test_next(self):
        # empty set raises StopIteration
        self.assertRaises(StopIteration, self.mab.next)

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
