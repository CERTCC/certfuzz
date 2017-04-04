'''
Created on Feb 14, 2012

@organization: cert.org
'''

import unittest
import os
import shutil
from certfuzz.fuzzers.bytemut import fuzz
from certfuzz.fuzzers.crmut import CRMutFuzzer
from test_certfuzz.mocks import MockSeedfile, MockRange
import tempfile
from certfuzz.fuzztools.hamming import bytewise_hd
import copy

class Test(unittest.TestCase):

    def setUp(self):
        self.sf = seedfile_obj = MockSeedfile()
        self.sf.value = bytearray(self.sf.value)
        self.chars_inserted = 0
        for i in range(0, len(self.sf.value), 10):
            self.sf.value[i] = 0x0D
            self.chars_inserted += 1

        self.tempdir = tempfile.mkdtemp()
        self.outdir = outdir_base = tempfile.mkdtemp(prefix='outdir_base',
                                                     dir=self.tempdir)
        iteration = 0
        self.options = {'min_ratio': 0.1, 'max_ratio': 0.2}
        self.args = (seedfile_obj, outdir_base, iteration, self.options)

    def tearDown(self):
        shutil.rmtree(self.tempdir)

    def _fail_if_not_fuzzed(self, fuzzed):
        for c in fuzzed:
            if c == 'A' or c == 0x0D:
                continue
            else:
                # skip over the else: clause
                break
        else:
            self.fail('Input not fuzzed')

    def _test_fuzz(self, inputlen=1000, iterations=100, rangelist=None):
        _input = bytearray('A' * inputlen)
        # sub in null chars
        chars_inserted = 0
        for i in range(0, inputlen, 10):
            _input[i] = 0x0D
            chars_inserted += 1

        for i in range(iterations):
            fuzzed = fuzz(fuzz_input=copy.copy(_input),
                                seed_val=0,
                                jump_idx=i,
                                ratio_min=0.1,
                                ratio_max=0.3,
                                range_list=rangelist,
                                fuzzable_chars=[0x0D]
                              )
            self.assertEqual(inputlen, len(fuzzed))
            self.assertNotEqual(_input, fuzzed)
            hd = bytewise_hd(_input, fuzzed)

            self.assertGreater(hd, 0)
            self.assertLessEqual(hd, chars_inserted)

            actual_ratio = hd / float(chars_inserted)
            self.assertGreaterEqual(actual_ratio, 0.1)
            self.assertLessEqual(actual_ratio, 0.3)

    def test_fuzz(self):
        self._test_fuzz()

    def test_fuzz_longinput(self):
        '''
        Test fuzz method with abnormally long input to find memory bugs
        '''
        self._test_fuzz(inputlen=10000000, iterations=2)

    def test_fuzz_rangelist(self):
        inputlen = 10000
        iterations = 100
        r = [(0, 100), (600, 1000), (3000, 10000)]
        _input = bytearray('A' * inputlen)
        # sub in null chars
        chars_inserted = 0
        for i in range(0, inputlen, 10):
            _input[i] = 0x0D
            chars_inserted += 1

        for i in range(iterations):
            fuzzed = fuzz(fuzz_input=copy.copy(_input),
                                seed_val=0,
                                jump_idx=i,
                                ratio_min=0.1,
                                ratio_max=0.3,
                                range_list=r,
                                fuzzable_chars=[0x0D],
                              )
            self.assertEqual(inputlen, len(fuzzed))
            self.assertNotEqual(_input, fuzzed)

            for (a, b) in r:
                # make sure we didn't change the exclude ranges
                self.assertEqual(_input[a:b + 1], fuzzed[a:b + 1])

            hd = bytewise_hd(_input, fuzzed)

            self.assertGreater(hd, 0)
            self.assertLess(hd, chars_inserted)

            # we excluded all but 2500 bytes in r above
            actual_ratio = hd / 2500.0
            self.assertGreaterEqual(actual_ratio, 0.01)
            self.assertLessEqual(actual_ratio, 0.03)

    def test_nullmutfuzzer_fuzz(self):
        self.assertTrue(self.sf.len > 0)
        for i in range(100):
            with CRMutFuzzer(*self.args) as f:
                f.iteration = i
                f._fuzz()
                # same length, different output
                self.assertEqual(self.sf.len, len(f.output))
                self._fail_if_not_fuzzed(f.input)
                # confirm ratio
#                self.assertGreaterEqual(f.fuzzed_byte_ratio() / self.chars_inserted, MockRange().min)
#                self.assertLessEqual(f.fuzzed_byte_ratio() / self.chars_inserted, MockRange().max)

    def test_consistency(self):
        # ensure that we get the same result 20 times in a row
        # for 50 different iterations
        last_result = None
        last_x = None
        for x in range(50):
            if x != last_x:
                last_result = None
            last_x = x
            for _ in range(20):
                with CRMutFuzzer(self.sf, self.outdir, x, self.options) as f:
                    f._fuzz()
                    result = str(f.output)
                    if last_result:
                        self.assertEqual(result, last_result)
                    else:
                        last_result = result

#    def test_is_minimizable(self):
#        f = CRMutFuzzer(*self.args)
#        self.assertTrue(f.is_minimizable)

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
