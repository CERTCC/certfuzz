'''
Created on Feb 14, 2014

@organization: cert.org
'''
import unittest
from certfuzz.campaign.campaign_linux import LinuxCampaign, check_program_file_type
import tempfile
import os
import shutil


class Test(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_check_program_file_type(self):
        fd, fname = tempfile.mkstemp(dir=self.tmpdir, text=True)
        os.write(fd, 'sometext')
        os.close(fd)
        self.assertTrue(check_program_file_type('text', fname))

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
