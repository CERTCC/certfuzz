'''
Created on Jan 29, 2016

@author: adh
'''
import unittest
from certfuzz.analyzers.drillresults import drillresults
from test_certfuzz.mocks import MockCfg, MockTestcase, MockFuzzedFile
import tempfile
import shutil
import os

go_count = 0
process_count = 0


class MockTcb(object):
    details = {'fuzzedfile': 'foo',
               'exceptions': {}, }
    score = 15
    crash_hash = '0123456789abcdef'

    def __init__(self, *args, **kwargs):
        self.go_count = 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def go(self):
        global go_count
        go_count += 1


def _inc_proc_count(*args):
    global process_count

    process_count += 1


class Test(unittest.TestCase):

    def setUp(self):
        global go_count
        go_count = 0

        global process_count
        process_count = 0

        self.cfg = MockCfg()
        self.tc = MockTestcase()
        self.dra = drillresults.LinuxDrillResults(self.cfg, self.tc)

        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)
        pass

    def testInit(self):
        self.assertTrue('debugger' in self.dra.cfg)

    def test_go(self):
        fd, ff = tempfile.mkstemp(prefix='fuzzed-', dir=self.tmpdir)
        os.close(fd)

        dbgf = os.path.join(
            self.tmpdir, '{}.{}'.format(ff, self.dra.testcase.debugger_extension))
        # touch the file
        open(dbgf, 'w').close()

        self.dra.testcase.dbg_files = {0: 'dbgf'}
        self.dra.testcase.fuzzedfile = MockFuzzedFile(ff)
        self.dra._tcb_cls = MockTcb
        self.dra._process_tcb = _inc_proc_count

        fd, of = tempfile.mkstemp(dir=self.tmpdir)
        os.close(fd)
        self.dra.outfile = of

        self.assertEqual(0, go_count)
        self.assertEqual(0, process_count)
        self.dra.go()
        self.assertEqual(1, go_count)
        self.assertEqual(1, process_count)

    def test_process_tcb(self):
        tcb = MockTcb()

        self.assertEqual(0, len(self.dra.output_lines))
        self.dra._process_tcb(tcb)
        # should be 2 lines if tcb is uninteresting
        self.assertEqual(2, len(self.dra.output_lines))

        self.assertTrue(MockTcb.crash_hash in self.dra.output_lines[0])
        self.assertTrue(str(MockTcb.score) in self.dra.output_lines[0])
        self.assertTrue(
            MockTcb.details['fuzzedfile'] in self.dra.output_lines[1])

    def test_write_outfile(self):
        fd, f = tempfile.mkstemp(
            suffix='-fuzzed', prefix='test-', dir=self.tmpdir)
        os.close(fd)

        self.dra.output_lines = ['a', 'b', 'c']
        self.dra.outfile = f

        os.remove(f)
        self.assertFalse(os.path.exists(f))
        self.dra._write_outfile()
        self.assertTrue(os.path.exists(f))

        with open(f, 'rb') as fp:
            contents = fp.read()
            self.assertTrue('a' in contents)
            self.assertTrue('b' in contents)
            self.assertTrue('c' in contents)

    def test_getfile(self):
        x = 'asdfghjklqwertyuiop'
        self.assertTrue(drillresults.get_file(x).startswith(x))
        self.assertTrue(
            drillresults.get_file(x).endswith(drillresults.OUTFILE_EXT))


if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
