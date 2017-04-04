'''
Created on Jul 2, 2014

@organization: cert.org
'''
import unittest
from certfuzz.analyzers.drillresults import testcasebundle_base
import tempfile
import shutil
import os
from certfuzz.drillresults.errors import TestCaseBundleError
import re


class TCB(testcasebundle_base.TestCaseBundle):
    really_exploitable = []

    def _64bit_addr_fixup(self, faddr, iaddr):
        return faddr, iaddr

    def _64bit_target_app(self):
        pass

    def _check_64bit(self):
        pass

    def _get_classification(self):
        pass

    def _get_shortdesc(self):
        pass

    def _look_for_loaded_module(self, iaddr, line):
        pass

    def get_instr(self):
        pass

    def get_instr_addr(self):
        return '0xdeadbeef'

    def get_return_addr(self):
        testcasebundle_base.TestCaseBundle.get_return_addr(self)


class Test(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.tcb = self._minimal_tcb()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_tcb_is_metaclass(self):
        self.assertTrue(
            hasattr(testcasebundle_base.TestCaseBundle, '__metaclass__'))

        # should raise a type error if you try to instantiate it
        self.assertRaises(TypeError, testcasebundle_base.TestCaseBundle)

    def _minimal_tcb(self):
        dbgf = os.path.join(self.tmpdir, '_debugfile')
        tcf = os.path.join(self.tmpdir, '_testcasefile')
        crash_sig = 'abracadabra'
        with open(dbgf, 'wb') as fp:
            fp.write('foo\n')
        with open(tcf, 'wb') as fp:
            fp.write('bar\n')
        return TCB(dbgf, tcf, crash_sig)

    def test_init(self):
        dbgf = os.path.join(self.tmpdir, 'debugfile')
        tcf = os.path.join(self.tmpdir, 'testcasefile')
        crash_sig = 'abracadabra'

        # the files don't exist. we should get an error
        self.assertRaises(TestCaseBundleError, TCB, dbgf, tcf, crash_sig)

        with open(dbgf, 'wb') as fp:
            fp.write('foo\n')

        # the tc don't exist. we should get an error
        self.assertRaises(TestCaseBundleError, TCB, dbgf, tcf, crash_sig)

        with open(tcf, 'wb') as fp:
            fp.write('bar\n')

        tcb = TCB(dbgf, tcf, crash_sig)
        self.assertEqual(dbgf, tcb.dbg_outfile)
        self.assertEqual(tcf, tcb.testcase_file)
        self.assertEqual(crash_sig, tcb.crash_hash)
        self.assertFalse(tcb.ignore_jit)

        self.assertTrue('foo' in tcb.reporttext)
        self.assertTrue('bar' in tcb.crasherdata)
        self.assertEqual(self.tmpdir, tcb.current_dir)

        self.assertFalse(tcb.details['reallyexploitable'])
        self.assertEqual(tcf, tcb.details['fuzzedfile'])

        self.assertEqual(100, tcb.score)
        self.assertFalse(tcb._64bit_debugger)
        self.assertEqual(None, tcb.classification)
        self.assertEqual(None, tcb.shortdesc)

    def test_runtime_context(self):
        self.assertTrue(hasattr(self.tcb, '__enter__'))
        self.assertTrue(hasattr(self.tcb, '__exit__'))

    def test_format_addr(self):
        # not 64 bit
        self.tcb._64bit_target_app = False
        for x in range(15):
            faddr = 'a' * (x + 1)
            faddr_hex = '0x' + faddr
            result = self.tcb.format_addr(faddr_hex)
            self.assertEqual(8, len(result))
            if len(result) >= len(faddr):
                self.assertTrue(faddr in result)
            else:
                trunc_faddr = faddr[-len(result):]
                self.assertTrue(trunc_faddr in result)

        # 64 bit padding
        self.tcb._64bit_target_app = True
        for x in range(15):
            faddr = 'a' * (x + 1)
            faddr_hex = '0x' + faddr
            result = self.tcb.format_addr(faddr_hex)
            self.assertEqual(16, len(result))
            self.assertTrue(faddr in result)

    def test_pc_in_mapped_address(self):
        self.assertEqual('', self.tcb.pc_in_mapped_address(None))

        self.tcb.reporttext = '\n'.join('abcdefghijklmnopqrstuvwxyz')
        self.assertEqual('unloaded', self.tcb.pc_in_mapped_address('zzz'))

        # fake out the loaded module check
        self.tcb._look_for_loaded_module = lambda x, y: 'foo'
        self.assertEqual('foo', self.tcb.pc_in_mapped_address('zzz'))

    def test_get_ex_num(self):
        self.assertEqual(0, self.tcb.get_ex_num())

    def test_match_rgx(self):
        self.tcb.reporttext = 'abc\ndef\nghi\n'
        rgx = re.compile('.+(h)')
        # return just the match
        func = lambda x, y: x.group(1)
        self.assertEqual('h', self.tcb._match_rgx(rgx, func))

        # return the line containing the match
        func = lambda x, y: y
        self.assertEqual('ghi', self.tcb._match_rgx(rgx, func))

    def test_record_exception(self):
        pass

    def test_score_interesting(self):
        # nothing to score gets an empty list
        scores = self.tcb._score_interesting()
        self.assertEqual(0, len(scores))

        xc = {'pcmodule': 'unloaded',
              'shortdesc': 'wow'}

        self.tcb.details['exceptions'] = {0: xc}
        scores = self.tcb._score_interesting()
        self.assertEqual(1, len(scores))
        self.assertTrue(20 in scores)

        self.tcb.re_set.add('wow')
        xc['efa'] = 'deadbeef'
        xc['EIF'] = False
        scores = self.tcb._score_interesting()
        self.assertTrue(40 in scores)

        xc['pcmodule'] = 'something'
        xc['EIF'] = True
        scores = self.tcb._score_interesting()
        self.assertTrue(5 in scores)

        xc['efa'] = '0x0000'
        scores = self.tcb._score_interesting()
        self.assertTrue(20 in scores)

        xc['efa'] = '0x000000'
        scores = self.tcb._score_interesting()
        self.assertTrue(30 in scores)

        xc['efa'] = '0xffff'
        scores = self.tcb._score_interesting()
        self.assertTrue(20 in scores)

    def test_score_less_interesting(self):
        # nothing to score gets an empty list
        scores = self.tcb._score_less_interesting()
        self.assertEqual(0, len(scores))

        xc = {'pcmodule': 'unloaded',
              'efa': 'deadbeef',
              'EIF': False}

        self.tcb.details['exceptions'] = {0: xc}
        scores = self.tcb._score_less_interesting()
        self.assertEqual(1, len(scores))
        self.assertTrue(20 in scores)

        xc['pcmodule'] = 'something'
        xc['EIF'] = True
        scores = self.tcb._score_less_interesting()
        self.assertTrue(50 in scores)

        xc['efa'] = '0x0000'
        scores = self.tcb._score_less_interesting()
        self.assertTrue(60 in scores)

        xc['efa'] = '0x000000'
        scores = self.tcb._score_less_interesting()
        self.assertTrue(70 in scores)

        xc['efa'] = '0xffff'
        scores = self.tcb._score_less_interesting()
        self.assertTrue(60 in scores)


if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
