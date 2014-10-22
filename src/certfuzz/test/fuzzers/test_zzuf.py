'''
Created on Oct 22, 2014

@organization: cert.org
'''
import unittest
from certfuzz.test.mocks import MockSeedfile
import tempfile
import shutil
from certfuzz.fuzzers.zzuf import ZzufFuzzer
import hashlib


class Test(unittest.TestCase):

    def setUp(self):
        self.sf = seedfile_obj = MockSeedfile()
        self.tempdir = tempfile.mkdtemp()
        self.outdir = outdir_base = tempfile.mkdtemp(prefix='outdir_base',
                                                     dir=self.tempdir)
        rng_seed = 0
        iteration = 0
        self.options = {}
#        self.options = {'min_ratio': 0.1, 'max_ratio': 0.2}
        self.args = (seedfile_obj, outdir_base, rng_seed, iteration, self.options)

    def tearDown(self):
        shutil.rmtree(self.tempdir)

    def _fail_if_not_fuzzed(self, fuzzed):
        for c in fuzzed:
            if c != 'A':
                break
        else:
            self.fail('Input not fuzzed')

    def test_is_minimizable(self):
        f = ZzufFuzzer(*self.args)
        self.assertTrue(f.is_minimizable)

    def test_fuzz(self):
        self.assertTrue(self.sf.len > 0)
        fuzzed_output_seen = set()
        for i in xrange(200):
            with ZzufFuzzer(*self.args) as f:
                f.iteration = i
                f._fuzz()
                # same length, different output
                self.assertEqual(self.sf.len, len(f.fuzzed))
                self._fail_if_not_fuzzed(f.fuzzed)

                # check for no repeats
                md5 = hashlib.md5(f.fuzzed).hexdigest()
                if md5 in fuzzed_output_seen:
                    self.fail('Fuzzer repeated output: %s' % md5)
                else:
                    fuzzed_output_seen.add(md5)

                # confirm ratio
#                self.assertAlmostEqual(f.ratio, f.fuzzed_bit_ratio(), 2)


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
