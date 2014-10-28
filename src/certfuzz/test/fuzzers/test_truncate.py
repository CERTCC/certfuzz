'''
Created on Mar 21, 2012

@organization: cert.org
'''

import unittest
from certfuzz.fuzzers.truncate import TruncateFuzzer
import certfuzz.fuzzers.drop
import shutil
from certfuzz.fuzzers.errors import FuzzerExhaustedError
import logging
from certfuzz.test import MockSeedfile
import tempfile

certfuzz.fuzzers.drop.logger.setLevel(logging.WARNING)


class Test(unittest.TestCase):

    def setUp(self):
        self.sf = seedfile_obj = MockSeedfile()
        self.tempdir = tempfile.mkdtemp()
        self.outdir = outdir_base = tempfile.mkdtemp(prefix='outdir_base',
                                                     dir=self.tempdir)
        rng_seed = 0
        iteration = 0
        options = {}
        self.args = (seedfile_obj, outdir_base, rng_seed, iteration, options)

    def tearDown(self):
        shutil.rmtree(self.tempdir, ignore_errors=True)

    def test_fuzzer_class(self):
        self.assertEqual(certfuzz.fuzzers.truncate._fuzzer_class, TruncateFuzzer)

    def test_fuzz_in_range(self):
        for x in range(self.sf.len - 1):
            self.sf.tries = x
            with TruncateFuzzer(*self.args) as f:
                f._fuzz()
                n_expected = self.sf.len - self.sf.tries - 1
                self.assertEqual(len(f.output), n_expected)

    def test_fuzz_out_of_range(self):
        self.sf.tries = self.sf.len + 1
        with TruncateFuzzer(*self.args) as f:
            self.assertRaises(FuzzerExhaustedError, f._fuzz)

    def test_is_not_minimizable(self):
        f = TruncateFuzzer(*self.args)
        self.assertFalse(f.is_minimizable)


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
