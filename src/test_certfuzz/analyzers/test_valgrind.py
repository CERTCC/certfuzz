import os
from certfuzz.analyzers.valgrind import Valgrind

'''
Created on Apr 8, 2011

@organization: cert.org
'''
import unittest
from test_certfuzz.mocks import MockFixupCfg

class Mock(object):
    pass

class Test(unittest.TestCase):
    def delete_file(self, f):
        os.remove(f)
        self.assertFalse(os.path.exists(f))

    def setUp(self):
        cfg = MockFixupCfg()

        crash = Mock()
        crash.fuzzedfile = Mock()
        crash.fuzzedfile.path = "foo"
        crash.fuzzedfile.dirname = 'foodir'
        self.vg = Valgrind(cfg, crash)

    def tearDown(self):
        pass

    def test_get_valgrind_cmdline(self):
        result = self.vg._get_cmdline()
        self.assertTrue('valgrind' in result)
        self.assertTrue('b' in result)
        self.assertTrue('c' in result)
        self.assertTrue('d' in result)
        self.assertTrue('foo' in result)

    def test_get_valgrind(self):
        # cannot test directly, see test_get_valgrind_cmdline
        pass

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
