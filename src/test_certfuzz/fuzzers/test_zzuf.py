'''
Created on Oct 22, 2014

@organization: cert.org
'''
import unittest
from test_certfuzz.mocks import MockSeedfile
import tempfile
import shutil
from certfuzz.fuzzers.zzuf import ZzufFuzzer
import hashlib
import os
from certfuzz.fuzzers.errors import FuzzerNotFoundError


class Test(unittest.TestCase):

    def setUp(self):
        # zzuf might not be in the default paths, so check a few other
        # locations too
        alternate_bin_locs = set(['/opt/local/bin'])
        alt_bin_locs_exist = (l for l in alternate_bin_locs if os.path.exists(l))
        add_locs = (l for l in alt_bin_locs_exist if not l in os.environ['PATH'])
        for loc in add_locs:
            os.environ['PATH'] += os.pathsep + loc

        self.sf = seedfile_obj = MockSeedfile()
        self.tempdir = tempfile.mkdtemp()
        self.outdir = outdir_base = tempfile.mkdtemp(prefix='outdir_base',
                                                     dir=self.tempdir)

        iteration = 0
        self.options = {}
#        self.options = {'min_ratio': 0.1, 'max_ratio': 0.2}
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
        f = ZzufFuzzer(*self.args)
        self.assertTrue(f.is_minimizable)

    def test_fuzz(self):
        self.assertTrue(self.sf.len > 0)
        fuzzed_output_seen = set()
        try:
            for i in range(200):
                with ZzufFuzzer(*self.args) as f:
                    f.iteration = i
                    f._fuzz()
                    # same length, different output
                    self.assertEqual(self.sf.len, len(f.output))
                    self._fail_if_not_fuzzed(f.output)

                    # check for no repeats
                    md5 = hashlib.md5(f.output).hexdigest()
                    if md5 in fuzzed_output_seen:
                        self.fail('Fuzzer repeated output: %s' % md5)
                    else:
                        fuzzed_output_seen.add(md5)
        except FuzzerNotFoundError as e:
            self.skipTest("zzuf not found in path")

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
