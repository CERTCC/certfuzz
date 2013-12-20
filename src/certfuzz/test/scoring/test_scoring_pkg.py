'''
Created on Feb 22, 2013

@organization: cert.org
'''
import unittest
from certfuzz import scoring

class Test(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def testName(self):
        names = ['ScorableSetError', 'ScorableThingError', 'ScoringError', 'ScorableSet2', 'ScorableThing']

        for name in names:
            self.assertTrue(hasattr(scoring, name))

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
