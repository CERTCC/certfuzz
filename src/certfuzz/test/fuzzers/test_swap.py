'''
Created on Apr 10, 2012

@organization: cert.org
'''
import unittest
from certfuzz.fuzzers.swap import SwapFuzzer
from certfuzz.test import MockSeedfile
from certfuzz.fuzzers.errors import FuzzerExhaustedError
import shutil
import tempfile


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

    def test_fuzz(self):
        self.sf.value = "ABCDE"
        with SwapFuzzer(*self.args) as f:
            self.assertEqual(f.output, None)
            self.sf.tries = 0
            f._fuzz()
            self.assertEqual(f.output, "BACDE")

        self.sf.value = "ABCDE"
        with SwapFuzzer(*self.args) as f:
            self.assertEqual(f.output, None)
            self.sf.tries = 1
            self.sf.value = "ABCDE"
            f._fuzz()
            self.assertEqual(f.output, "ACBDE")

        self.sf.value = "ABCDE"
        with SwapFuzzer(*self.args) as f:
            self.sf.tries = 3
            self.sf.value = "ABCDE"
            f._fuzz()
            self.assertEqual(f.output, "ABCED")

    def test_fuzz_out_of_range(self):
        self.sf.tries = len(self.sf.value)
        with SwapFuzzer(*self.args) as f:
            self.assertRaises(FuzzerExhaustedError, f._fuzz)

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
