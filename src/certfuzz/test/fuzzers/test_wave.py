'''
Created on Mar 21, 2012

@organization: cert.org
'''

import unittest
from certfuzz.fuzzers.wave import WaveFuzzer
import certfuzz.fuzzers.wave
import shutil
from certfuzz.fuzzers.errors import FuzzerExhaustedError
import logging
from certfuzz.test.mocks import MockSeedfile
import tempfile

certfuzz.fuzzers.wave.logger.setLevel(logging.WARNING)


class Test(unittest.TestCase):

    def setUp(self):
        self.sf = seedfile_obj = MockSeedfile(sz=10)
        self.tempdir = tempfile.mkdtemp()
        self.outdir = outdir_base = tempfile.mkdtemp(prefix='outdir_base',
                                                     dir=self.tempdir)
        iteration = 0
        options = {}
        self.args = (seedfile_obj, outdir_base, iteration, options)

    def tearDown(self):
        shutil.rmtree(self.tempdir, ignore_errors=True)

    def test_fuzzer_class(self):
        self.assertEqual(certfuzz.fuzzers.wave._fuzzer_class, WaveFuzzer)

    def test_fuzz_in_range(self):
        for x in range(self.sf.len * 256):
            self.sf.tries = x
            with WaveFuzzer(*self.args) as f:
                f._fuzz()
                pos = x / 256  # note integer math
                val = x % 256
                self.assertEqual(f.output[pos], val)

    def test_fuzz_out_of_range(self):
        self.sf.tries = self.sf.len * 256 + 1
        with WaveFuzzer(*self.args) as f:
            self.assertRaises(FuzzerExhaustedError, f._fuzz)

    def test_is_not_minimizable(self):
        f = WaveFuzzer(*self.args)
        self.assertTrue(f.is_minimizable)


if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
