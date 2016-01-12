'''
Created on Jan 12, 2016

@author: adh
'''
import unittest
from certfuzz.reporters import copy_files
import tempfile
import shutil
from test_certfuzz.mocks import MockTestcase
import os


class Test(unittest.TestCase):


    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)


    def testCopyFiles(self):
        tc = MockTestcase()
        tc.tempdir = tempfile.mkdtemp(dir=self.tmpdir)
        fh, tcfile = tempfile.mkstemp(dir=tc.tempdir)
        os.close(fh)

        target_dir = tempfile.mkdtemp(dir=self.tmpdir)

        # target dir is empty
        self.assertEqual([], os.listdir(target_dir))

        _path, fname = os.path.split(tcfile)

        # source dir has only one file
        self.assertEqual([fname], os.listdir(tc.tempdir))

        r = copy_files.CopyFilesReporter(tc, target_dir)
        with r:
            r.go()

        # target dir should contain an outdir with the file we copied
        outdir = os.path.join(target_dir, tc.signature)
        self.assertTrue(os.path.exists(outdir))
        self.assertEqual([fname], os.listdir(outdir))



if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
