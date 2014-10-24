'''
Created on Oct 22, 2014

@organization: cert.org
'''
import unittest
from certfuzz.runners.zzufrun import ZzufRunner
import shutil
import tempfile
import os


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


    def test_run(self):
        options = {}
        cmd_template = ''

        for i in xrange(100):
            with ZzufRunner(options, cmd_template, self.ff, self.tmpdir) as r:
                print r.__dict__
                r._run()

        self.assertTrue(False)
        pass

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
