'''
Created on Apr 8, 2011

@organization: cert.org
'''
import os
import tempfile
from certfuzz.fuzztools import hamming
from certfuzz.minimizer.minimizer_base import Minimizer
import shutil
from certfuzz.file_handlers.basicfile import BasicFile
import unittest
import certfuzz.minimizer.minimizer_base

class Mock(object):
    def __init__(self, *args, **kwargs):
        pass

class MockCfg(Mock):
    program = 'a'
    debugger_timeout = 1
    killprocname = 'a'
    exclude_unmapped_frames = False
    backtracelevels = 5

    def get_command_args_list(self, dummy):
        return tuple('abcd')

class MockCrasher(Mock):
    def __init__(self):
        fd, f = tempfile.mkstemp(suffix='.ext', prefix='fileroot')
        os.close(fd)
        self.fuzzedfile = BasicFile(f)
        self.debugger_template = 'foo'

    def set_debugger_template(self, dummy):
        pass

class MockDbgOut(Mock):
    is_crash = False
    total_stack_corruption = False

    def get_crash_signature(self, *dummyargs):
        return 'AAAAA'

class MockDebugger(Mock):
    def get(self):
        return MockDebugger

    def go(self):
        return MockDbgOut()

def _mock_dbg_get():
    return MockDebugger


class Test(unittest.TestCase):
    def delete_file(self, f):
        os.remove(f)
        self.assertFalse(os.path.exists(f))

    def setUp(self):
        self.cfg = MockCfg()
        self.crash = MockCrasher()

        certfuzz.minimizer.minimizer_base.debugger_get = _mock_dbg_get

        self.tempdir = tempfile.mkdtemp(prefix='minimizer_test_')
        self.crash_dst_dir = tempfile.mkdtemp(prefix='crash_', dir=self.tempdir)
        (fd, self.logfile) = tempfile.mkstemp(dir=self.tempdir)
        os.close(fd)
        os.remove(self.logfile)
        self.assertFalse(os.path.exists(self.logfile))
        certfuzz.minimizer.minimizer_base.debuggers = MockDebugger()

        self.m = Minimizer(cfg=self.cfg, crash=self.crash,
                           crash_dst_dir=self.crash_dst_dir,
                           logfile=self.logfile, tempdir=self.tempdir)

    def tearDown(self):
        shutil.rmtree(self.tempdir)

    def test_go(self):
        pass

    def test_have_we_seen_this_file_before(self):
        self.m.newfuzzed_md5 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

        self.assertFalse(self.m.have_we_seen_this_file_before())
        self.assertTrue(self.m.have_we_seen_this_file_before())

    def test_is_same_crash(self):
        pass

    def test_print_intermediate_log(self):
        pass

    def test_set_discard_chance(self):
        self.m.seed = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        self.m.fuzzed_content = "abcdefghijklmnopqrstuvwxyz"
        self.m.min_distance = hamming.bytewise_hd(self.m.seed, self.m.fuzzed_content)
        self.assertEqual(self.m.min_distance, 26)

        for tsg in xrange(1, 20):
            self.m.target_size_guess = tsg
            self.m.set_discard_chance()
            self.assertAlmostEqual(self.m.discard_chance, 1.0 / (1.0 + tsg))

    def test_set_n_misses(self):
        pass

    def test_swap_bytes(self):
        seed = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        fuzzed = "abcdefghijklmnopqrstuvwxyz"

        for dc in (0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9):
            self.m.discard_chance = dc
            self.m.seed = seed
            self.m.fuzzed_content = fuzzed
            self.m.min_distance = 26
            self.m.swap_func = self.m.bytewise_swap2
            self.m.swap_bytes()
            self.assertTrue(0 < self.m.newfuzzed_hd)
            self.assertTrue(self.m.newfuzzed_hd <= 26)
            self.assertNotEqual(self.m.newfuzzed, fuzzed)
            self.assertNotEqual(self.m.newfuzzed, seed)

    def test_update_probabilities(self):
        pass


if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
