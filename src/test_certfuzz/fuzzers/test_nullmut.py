'''
Created on Feb 14, 2012

@organization: cert.org
'''

import unittest
import os
import shutil
from certfuzz.fuzzers.nullmut import NullMutFuzzer
from test_certfuzz.mocks import MockSeedfile, MockRange
import tempfile
from certfuzz.fuzztools.hamming import bytewise_hd

class Test(unittest.TestCase):

    def setUp(self):
        self.sf = seedfile_obj = MockSeedfile()
        self.sf.value = bytearray(self.sf.value)
        self.nulls_inserted = 0
        for i in range(0, len(self.sf.value), 10):
            self.sf.value[i] = 0x00
            self.nulls_inserted += 1

        self.tempdir = tempfile.mkdtemp()
        self.outdir = outdir_base = tempfile.mkdtemp(prefix='outdir_base',
                                                     dir=self.tempdir)
        iteration = 0
        self.options = {'min_ratio': 0.1, 'max_ratio': 0.2}
        self.args = (seedfile_obj, outdir_base, iteration, self.options)

    def tearDown(self):
        shutil.rmtree(self.tempdir)

    def test_is_minimizable(self):
        f = NullMutFuzzer(*self.args)
        self.assertTrue(f.is_minimizable)

    def test_fuzzable_chars(self):
        f = NullMutFuzzer(*self.args)
        self.assertTrue(0x00 in f.fuzzable_chars)

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
