'''
Created on Jan 10, 2014

@author: adh
'''
import unittest
from certfuzz.campaign.campaign_windows import WindowsCampaign
import tempfile
import shutil
from certfuzz.campaign.config.errors import ConfigError


class Test(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_init_without_config(self):
        _fd, cfgfile = tempfile.mkstemp(suffix=".cfg", dir=self.tmpdir, text=True)
        self.assertRaises(ConfigError, WindowsCampaign, cfgfile)

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
