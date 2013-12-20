from certfuzz.fuzztools.process_killer import ProcessKiller

'''
Created on Apr 8, 2011

@organization: cert.org
'''
import unittest

class Test(unittest.TestCase):

    def setUp(self):
        self.pk = ProcessKiller(*tuple('abc'))

    def tearDown(self):
        pass

    def test_get_cmdline(self):
        self.assertTrue('a b c' in self.pk._get_cmdline())

    def test_spawn_process_killer(self):
        # cannot test directly, see test_get_spawn_process_killer_cmdline()
        pass

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
