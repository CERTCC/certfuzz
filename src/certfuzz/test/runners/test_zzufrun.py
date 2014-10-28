'''
Created on Oct 22, 2014

@organization: cert.org
'''
import unittest
from certfuzz.runners.zzufrun import ZzufRunner
import shutil
import tempfile
import os
import stat
from certfuzz.runners.errors import RunnerNotFoundError


class Test(unittest.TestCase):
    def setUp(self):
        # zzuf might not be in the default paths, so check a few other
        # locations too
        alternate_bin_locs = set(['/opt/local/bin'])
        alt_bin_locs_exist = (l for l in alternate_bin_locs if os.path.exists(l))
        add_locs = (l for l in alt_bin_locs_exist if not l in os.environ['PATH'])
        for loc in add_locs:
            os.environ['PATH'] += os.pathsep + loc

        self._filecontent = 'A' * 1000

        self.tmpdir = tempfile.mkdtemp()
        fd, fname = tempfile.mkstemp(suffix='fuzzed', dir=self.tmpdir)
        os.write(fd, self._filecontent)
        os.close(fd)

        self.ff = fname

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_quiet_flag(self):
        zr = ZzufRunner(options={'quiet': True}, cmd_template=None,
                        fuzzed_file=None, workingdir_base=self.tmpdir)
        self.assertTrue(zr._quiet)
        with zr:
            self.assertTrue('--quiet' in zr._zzuf_args)

        zr = ZzufRunner(options={'quiet': False}, cmd_template=None,
                        fuzzed_file=None, workingdir_base=self.tmpdir)
        self.assertFalse(zr._quiet)
        with zr:
            self.assertFalse('--quiet' in zr._zzuf_args)

    def test_find_zzuf(self):
        (fd, fname) = tempfile.mkstemp(prefix='zzufrun_test_', dir=self.tmpdir)
        os.close(fd)
        os.remove(fname)
        self.assertFalse(os.path.exists(fname))

        for exe in ['/bin/ls', fname]:
            zr = ZzufRunner(options={}, cmd_template=None,
                            fuzzed_file=None, workingdir_base=self.tmpdir)
            self.assertEqual(zr._zzuf_basename, 'zzuf')

            _basename = os.path.basename(exe)
            zr._zzuf_basename = _basename

            self.assertEqual(None, zr._zzuf_loc)
            if os.path.exists(exe):
                zr._find_zzuf()
                self.assertEqual(exe, zr._zzuf_loc)
            else:
                self.assertRaises(RunnerNotFoundError, zr._find_zzuf)

    def test_run(self):
        options = {}
        cmd_template = ''

        touch = '/usr/bin/touch'
        if not os.path.exists(touch):
            # bail out if touch doesn't exist
            return

        for _ in xrange(100):
            zr = ZzufRunner(options, cmd_template, self.ff, self.tmpdir)
            fd, fname = tempfile.mkstemp(prefix='zzufrun_test_', dir=self.tmpdir)
            os.close(fd)
            os.remove(fname)
            with zr:
                # we're really just testing the structure of the _run method,
                # not whether zzuf works
                zr._zzuf_args = [touch, fname]
                self.assertFalse(os.path.exists(fname))
                zr._run()
                self.assertTrue(os.path.exists(fname))


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
