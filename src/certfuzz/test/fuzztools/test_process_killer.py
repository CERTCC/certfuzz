'''
Created on Apr 8, 2011

@organization: cert.org
'''
import unittest
from certfuzz.fuzztools.process_killer import ProcessKiller


class Test(unittest.TestCase):

    def setUp(self):
        self.pk = ProcessKiller(*tuple('bc'))

    def tearDown(self):
        pass

    def test_get_cmdline(self):
        self.pk._set_cmdline()
        self.assertTrue('b c' in self.pk.cmdline)

    def test_spawn_process_killer(self):
        # cannot test directly, see test_get_spawn_process_killer_cmdline()
        pass

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
