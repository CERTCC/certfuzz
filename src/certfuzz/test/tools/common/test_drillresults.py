'''
Created on Jul 1, 2014

@organization: cert.org
'''
import unittest
from certfuzz.tools.common import drillresults
import tempfile
import shutil
import os

alphabet = 'abcdefghijklmnopqrstuvwxyz'

class MockRd(drillresults.ResultDriller):
    # really_exploitable expects a list
    really_exploitable = list(alphabet)

    def _check_report(self):
        pass

    def _platform_find_testcases(self):
        pass

    def check_64bit(self):
        pass


class Test(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_all_registers_in_set(self):
        for r in drillresults.registers:
            self.assertTrue(r in drillresults.reg_set)

    def test_all_64b_registers_in_set(self):
        for r in drillresults.registers64:
            self.assertTrue(r in drillresults.reg64_set)

    def test_build_arg_parser(self):
        p = drillresults._build_arg_parser()

        # not sure what else to test, so let's just make
        # sure that the thing we get back at least has
        # a parse_args method
        self.assertTrue(hasattr(p, 'parse_args'))
        self.assertTrue(hasattr(p.parse_args, '__call__'))

    def test_parse_args(self):
        # not much to test here
        pass

    def test_read_file(self):
        fd, f = tempfile.mkstemp(text=True)
        os.write(fd, 'fizzle')
        os.close(fd)
        result = drillresults.read_text_file(f)
        self.assertEqual('fizzle', result)
        os.remove(f)

    def test_carve(self):
        s = 'redbluegreenyellowred'
        r = drillresults.carve(s, 'red', 'red')
        self.assertEqual('bluegreenyellow', r)

        r = drillresults.carve(s, 'blue', 'yellow')
        self.assertEqual('green', r)

    def test_carve2(self):
        # won't match
        s = 'redbluegreenyellowred'
        r = drillresults.carve2(s)
        self.assertEqual('', r)

        # should match
        for s in ['Exception Faulting Address: MATCHME\n',
                  'si_addr:$2 = (void *)MATCHME\n']:
            r = drillresults.carve2(s)
            self.assertEqual('MATCHME', r)

    def test_is_number(self):
        expect_true = ['1', '1e4', '10.1231']
        expect_false = ['abcdef', '0xfffe1010', '0b010001']
        for s in expect_true:
            self.assertTrue(drillresults.is_number(s))
        for s in expect_false:
            self.assertFalse(drillresults.is_number(s))

    def test_rd_acts_as_metaclass(self):
        self.assertRaises(TypeError, drillresults.ResultDriller)

    def test_rd(self):
        rd = MockRd()
        for letter in alphabet:
            self.assertTrue(letter in rd.re_set)


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
