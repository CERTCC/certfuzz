from certfuzz.fuzztools.zzuf import Zzuf
from certfuzz.fuzztools.zzuf import ZzufTestCase
import re
'''
Created on Apr 8, 2011

@organization: cert.org
'''

import unittest

class Test(unittest.TestCase):

    def setUp(self):
        self.z = Zzuf('a', 1, 2, 'd', 'e', 'f',
                      True,
                      0.01,
                      0.1,
                      100
                      )
        pass

    def tearDown(self):
        pass

    def test_testcase_set_cmdline(self):
        expected = "cat a | zzuf -sb -rc > d"
        testcase = ZzufTestCase('a', 'b', 'c', 'd')
        self.assertEqual(testcase.cmdline, expected)

    def test_generate_test_case(self):
        # can not test without real data
        # see test_testcase_set_cmdline()
        pass

    def test_get_go_fuzz_cmdline(self):
        self.z.dir = 'dir'
        self.z.zzuf_args = 'args'
        self.z.get_command = 'get_command'
        self.z.file = 'file'
        expected = "cd dir && zzuf args d 2> file"
        self.assertEqual(self.z._get_go_fuzz_cmdline(), expected)

    def test_go_fuzz(self):
        # cannot test nondestructively
        # see test_get_go_fuzz_cmdline()
        pass

    def test_get_zzuf_args(self):

        zzuf_args = self.z._get_zzuf_args()

        splitparts = lambda L: [re.sub('^--', '', s) for s in L.split(' ')]

        # strip out the leading '--' from args to make it easier to verify
        parts = splitparts(zzuf_args)

        [self.assertTrue(s in parts, s) for s in ('signal', 'quiet')]
        self.assertTrue('max-crashes=1' in parts)
        self.assertTrue('opmode=copy' in parts)

        # check for presence of ratiomin and ratiomax
        ratio_item = [x for x in parts if "ratio" in x].pop()
        ratio_item = ratio_item.split('=')[1]  # take the part after the equals sign
        (rmin, rmax) = ratio_item.split(':')
        self.assertEqual(float(rmin), 0.01)
        self.assertEqual(float(rmax), 0.1)

        # TODO check for presence of timeout
        max_usertime_item = [x for x in parts if "usertime" in x].pop()
        max_usertime = max_usertime_item.split('=')[1]
        self.assertEqual(float(max_usertime), 100.00)

        # call _get_zzuf_args() again with copymode=False
        self.z.copymode = False
        zzuf_args = self.z._get_zzuf_args()

        # strip out the leading '--' from args to make it easier to verify
        parts = splitparts(zzuf_args)

        self.assertFalse('check-exit' in parts)
        self.assertFalse('opmode=copy' in parts)

        # check case where quiet is False
        self.z.quiet = False
        # strip out the leading '--' from args to make it easier to verify
        parts = splitparts(self.z._get_zzuf_args())
        self.assertFalse('quiet' in parts)

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
