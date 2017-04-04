'''
Created on Apr 10, 2012

@organization: cert.org
'''
import unittest
import tempfile
import os
from test_certfuzz.mocks import MockSeedfile
import shutil
from certfuzz.fuzzers.bitmut import BitMutFuzzer

class Test(unittest.TestCase):

    def setUp(self):
        self.sf = seedfile_obj = MockSeedfile()
        self.tempdir = tempfile.mkdtemp()
        self.outdir = outdir_base = tempfile.mkdtemp(prefix='outdir_base',
                                                     dir=self.tempdir)
        iteration = 0
        self.options = {}
        self.args = (seedfile_obj, outdir_base, iteration, self.options)

    def tearDown(self):
        shutil.rmtree(self.tempdir)

    def _fail_if_not_fuzzed(self, fuzzed):
        for c in fuzzed:
            if c != 'A':
                break
        else:
            self.fail('Input not fuzzed')

    def test_is_minimizable(self):
        f = BitMutFuzzer(*self.args)
        self.assertTrue(f.is_minimizable)

    def test_fuzz(self):
        self.assertTrue(self.sf.len > 0)
        for i in range(100):
            with BitMutFuzzer(*self.args) as f:
                f.iteration = i
                f._fuzz()
                # same length, different output
                self.assertEqual(self.sf.len, len(f.output))
                self._fail_if_not_fuzzed(f.output)
                # confirm ratio
#                self.assertAlmostEqual(f.ratio, f.fuzzed_bit_ratio(), 2)

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
