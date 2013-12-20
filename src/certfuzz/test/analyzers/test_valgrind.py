import os
from certfuzz.analyzers.valgrind import Valgrind

'''
Created on Apr 8, 2011

@organization: cert.org
'''
import unittest

class Mock(object):
    pass

class Test(unittest.TestCase):
    def delete_file(self, f):
        os.remove(f)
        self.assertFalse(os.path.exists(f))

    def setUp(self):
        cfg = Mock()
        cfg.valgrindtimeout = 1
        cfg.get_command_list = lambda x: ['x', 'y', 'z']

        crash = Mock()
        crash.fuzzedfile = Mock()
        crash.fuzzedfile.path = "foo"
        crash.fuzzedfile.dirname = 'foodir'
        crash.killprocname = 'bar'
        self.vg = Valgrind(cfg, crash)

    def tearDown(self):
        pass

    def test_get_valgrind_cmdline(self):
        expected = ["valgrind", "--log-file=foo.valgrind", "x", "y", "z"]

        self.assertEqual(self.vg._get_cmdline(), expected)

    def test_get_valgrind(self):
        # cannot test directly, see test_get_valgrind_cmdline
        pass

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
