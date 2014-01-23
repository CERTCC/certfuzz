'''
Created on Mar 23, 2012

@organization: cert.org
'''

import unittest
from certfuzz.iteration.iteration_windows import Iteration


class Test(unittest.TestCase):

    def setUp(self):
        args = list('0123456789ABCDE')
        args[3] = {'runoptions': {'keep_unique_faddr': False}}
        self.iteration = Iteration(*args)

    def tearDown(self):
        pass

    def testName(self):
        pass

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
