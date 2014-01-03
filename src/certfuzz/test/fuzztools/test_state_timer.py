'''
Created on Jan 3, 2014

@author: adh
'''
import unittest
from certfuzz.fuzztools import state_timer
import time


class Test(unittest.TestCase):
    def setUp(self):
        self.st = state_timer.StateTimer()

    def tearDown(self):
        pass

    def test__str__(self):
        # expect no commas in empty timer
        delim = self.st._delim
        self.assertFalse(delim in str(self.st))
        self.st.enter_state('foo')
        self.assertTrue('foo' in str(self.st))
        self.assertFalse(delim in str(self.st))
        self.st.enter_state('bar')
        self.assertTrue('foo' in str(self.st))
        self.assertTrue('bar' in str(self.st))
        self.assertTrue(delim in str(self.st))

    def test_enter_state(self):
        st = self.st

        self.assertEqual(0, len(st.timers))
        st.enter_state('alpha')
        self.assertEqual(1, len(st.timers))
        time.sleep(1)
        st.enter_state(None)
        self.assertEqual(1, len(st.timers))
        self.assertAlmostEqual(1.0, st.time_in('alpha'), 1)

        st.enter_state('alpha')
        self.assertEqual(1, len(st.timers))
        time.sleep(1)
        st.enter_state('beta')
        self.assertEqual(2, len(st.timers))
        self.assertAlmostEqual(2.0, st.time_in('alpha'), 1)
        self.assertEqual(0.0, st.time_in('beta'))
        time.sleep(1)
        st.enter_state(None)
        self.assertAlmostEqual(2.0, st.time_in('alpha'), 1)
        self.assertAlmostEqual(1.0, st.time_in('beta'), 1)

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
