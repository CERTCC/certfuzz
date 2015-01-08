'''
Created on Feb 14, 2014

@organization: cert.org
'''
import unittest
from certfuzz.campaign.campaign_linux import LinuxCampaign, check_program_file_type
import tempfile
import os
import shutil
from ConfigParser import NoSectionError
from certfuzz.config.errors import ConfigError


class Test(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        fd, cfgfile = tempfile.mkstemp(suffix=".yaml", dir=self.tmpdir, text=True)
        os.close(fd)
        import yaml
        data = {'campaign': {'id': 'foo'},
                'directories': {},
                'timeouts': {},
                'zzuf': {},
                'verifier': {},
                'target': {'cmdline': 'bar baz quux'},
                }
        with open(cfgfile, 'wb') as stream:
            yaml.dump(data, stream)

        self.campaign = LinuxCampaign(cfgfile)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_init_without_config(self):
        _fd, cfgfile = tempfile.mkstemp(suffix=".yaml", dir=self.tmpdir, text=True)
        self.assertRaises(ConfigError, LinuxCampaign, cfgfile)

    def test_check_program_file_type(self):
        fd, fname = tempfile.mkstemp(dir=self.tmpdir, text=True)
        os.write(fd, 'sometext')
        os.close(fd)
        self.assertTrue(check_program_file_type('text', fname))

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
