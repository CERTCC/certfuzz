'''
Created on Feb 14, 2012

@organization: cert.org
'''

import unittest
import os
from certfuzz.fuzzers.fuzzer_base import Fuzzer
from test_certfuzz.mocks import MockSeedfile
import shutil
from certfuzz.fuzzers.fuzzer_base import MinimizableFuzzer
import tempfile
from certfuzz.fuzzers.fuzzer_base import is_fuzzable as _fuzzable

class Test(unittest.TestCase):

    def setUp(self):
        self.sf = seedfile_obj = MockSeedfile()
        self.tempdir = tempfile.mkdtemp()
        self.outdir = outdir_base = tempfile.mkdtemp(prefix='outdir_base',
                                                     dir=self.tempdir)
        iteration = 0
        options = {}
        self.args = (seedfile_obj, outdir_base, iteration, options)

    def tearDown(self):
        shutil.rmtree(self.tempdir, ignore_errors=True)

    def test_read_input(self):
        with Fuzzer(*self.args) as f:
            self.assertEqual(f.input, self.sf.read())

    def test_no_write_if_not_fuzzed(self):
        with Fuzzer(*self.args) as f:
            self.assertFalse(os.path.exists(f.output_file_path), f.output_file_path)
            # if we haven't output, don't write
            f.output = None
            f.write_fuzzed()
            self.assertFalse(os.path.exists(f.output_file_path))

    def test_write_fuzzed(self):
        with Fuzzer(*self.args) as f:

            self.assertFalse(os.path.exists(f.output_file_path), f.output_file_path)

            # if we have output, write
            f.output = 'abcd'
            f.write_fuzzed()
            self.assertTrue(os.path.exists(f.output_file_path))
            self.assertEqual(os.path.getsize(f.output_file_path), len(f.output))
            with open(f.output_file_path, 'rb') as fd:
                written = fd.read()
                self.assertEqual(written, f.output)

    def test_minimizable_attribute(self):
        yes = MinimizableFuzzer(*self.args)
        self.assertTrue(yes.is_minimizable)

        no = Fuzzer(*self.args)
        self.assertFalse(no.is_minimizable)

    def test_fuzzable(self):
        r = [(0, 100), (600, 1000), (3000, 10000)]
        for x in range(10000):
            if 0 <= x <= 100:
                self.assertFalse(_fuzzable(x, r), 'x=%d' % x)
            elif 600 <= x <= 1000:
                self.assertFalse(_fuzzable(x, r), 'x=%d' % x)
            elif 3000 <= x <= 10000:
                self.assertFalse(_fuzzable(x, r), 'x=%d' % x)
            else:
                self.assertTrue(_fuzzable(x, r), 'x=%d' % x)


if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
