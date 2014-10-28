'''
Created on Mar 21, 2012

@organization: cert.org
'''

import unittest
from certfuzz.fuzzers.insert import InsertFuzzer
import certfuzz.fuzzers.insert
import shutil
from certfuzz.fuzzers.errors import FuzzerExhaustedError
import logging
from certfuzz.test import MockSeedfile
import tempfile

certfuzz.fuzzers.insert.logger.setLevel(logging.WARNING)


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
        self.assertEqual(certfuzz.fuzzers.insert._fuzzer_class, InsertFuzzer)

    def test_fuzz_in_range(self):
        for x in range(self.sf.len):
            self.sf.tries = x
            with InsertFuzzer(*self.args) as f:
                f._fuzz()
                self.assertEqual(len(f.output), self.sf.len + 1)
                self.assertEqual(chr(f.output[x + 1]), self.sf.value[x])
                if x > 0:
                    self.assertEqual(chr(f.output[x - 1]), self.sf.value[x - 1])

    def test_fuzz_out_of_range(self):
        self.sf.tries = self.sf.len + 1
        with InsertFuzzer(*self.args) as f:
            self.assertRaises(FuzzerExhaustedError, f._fuzz)

    def test_is_not_minimizable(self):
        f = InsertFuzzer(*self.args)
        self.assertFalse(f.is_minimizable)


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
