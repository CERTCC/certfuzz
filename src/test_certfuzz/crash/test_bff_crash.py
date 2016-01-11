'''
Created on Aug 3, 2011

@organization: cert.org
'''

import unittest
# from certfuzz.crash.bff_crash import Crash
from certfuzz.test.mocks import Mock
import tempfile
import os
import shutil

class MockConfig(Mock):
    def __init__(self, tmpdir):
        self.exclude_unmapped_frames = False
        self.testscase_tmp_dir = tmpdir

    def get_command_args_list(self, dummy):
        return list('abcdefg')

class MockFile(Mock):
    def __init__(self, tempdir):
        fd, f = tempfile.mkstemp(dir=tempdir)
        os.write(fd, 'A' * 80)
        os.close(fd)
        self.path = f
        self.basename = os.path.basename(f)

class Test(unittest.TestCase):

    def setUp(self):
        self.tempdir = tempfile.mkdtemp()
        args = list('0123456789')
        args[0] = MockConfig(self.tempdir)
        args[1] = MockFile(self.tempdir)
        args[2] = MockFile(self.tempdir)
        # TODO: write this test
#        self.c = Crash(*args)

    def tearDown(self):
        shutil.rmtree(self.tempdir)
        self.assertFalse(os.path.exists(self.tempdir))


if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
