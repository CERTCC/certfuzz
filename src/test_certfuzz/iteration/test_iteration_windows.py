'''
Created on Mar 23, 2012

@organization: cert.org
'''

import unittest
from certfuzz.iteration.iteration_windows import WindowsIteration
from test_certfuzz.mocks import MockFuzzer


class Test(unittest.TestCase):

    def setUp(self):
        # args:
        

#                 seedfile=None,
#                  seednum=None,
#                  workdirbase=None,
#                  outdir=None,
#                  sf_set=None,
#                  uniq_func=None,
#                  config=None,
#                  fuzzer_cls=None,
#                  runner_cls=None,
#                  cmd_template=None,
#                  debug=False,

        args = list('ABCDEFGHILM')
        args[6] = {'runoptions': {'keep_unique_faddr': False}}
        args[7] = MockFuzzer
        self.iteration = WindowsIteration(*args)

    def tearDown(self):
        pass

    def testName(self):
        pass

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
