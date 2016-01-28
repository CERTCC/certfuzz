'''
Created on Feb 14, 2014

@organization: cert.org
'''
import unittest
from certfuzz.campaign.campaign_linux import LinuxCampaign, check_program_file_type
import tempfile
import os
import shutil
from certfuzz.config.errors import ConfigError
import yaml


class Test(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        fd, cfgfile = tempfile.mkstemp(suffix=".yaml", dir=self.tmpdir, text=True)
        os.close(fd)

        data = {'campaign': {'id': 'foo'},
                'directories': {'seedfile_dir': tempfile.mkdtemp(prefix='seedfiles_', dir=self.tmpdir),
                                'results_dir': tempfile.mkdtemp(prefix='output_', dir=self.tmpdir),
                                'working_dir': tempfile.mkdtemp(prefix='local_', dir=self.tmpdir)},
                'timeouts': {},
                'verifier': {},
                'target': {'program': 'foo',
                           'cmdline_template': 'foo bar baz quux'},
                'runoptions':{'first_iteration':0,
                              'seed_interval': 10}
                }
        with open(cfgfile, 'wb') as stream:
            yaml.dump(data, stream)

        self.campaign = LinuxCampaign(cfgfile)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_init_without_config(self):
        # test empty config file
        _fd, cfgfile = tempfile.mkstemp(suffix=".yaml", dir=self.tmpdir, text=True)
        self.assertRaises(ConfigError, LinuxCampaign, cfgfile)

        # test non-existent config file
        os.unlink(cfgfile)
        self.assertFalse(os.path.exists(cfgfile))
        self.assertRaises(IOError,LinuxCampaign,cfgfile)


    def test_check_program_file_type(self):
        fd, fname = tempfile.mkstemp(dir=self.tmpdir, text=True)
        os.write(fd, 'sometext')
        os.close(fd)
        self.assertTrue(check_program_file_type('text', fname))

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
