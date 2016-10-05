'''
Created on Jan 13, 2016

@author: adh
'''
import unittest
import certfuzz.config.simple_loader
import tempfile
import shutil
import os
import yaml
from certfuzz.config.errors import ConfigError
from certfuzz.config.simple_loader import fixup_config
from test_certfuzz.mocks import MockCfg
import string


class Test(unittest.TestCase):

    def setUp(self):
        self.tempdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tempdir)

    def _write_yaml(self, thing=None):
        if thing is None:
            thing = dict([(y, x) for x, y in enumerate("abcd")])
        fd, f = tempfile.mkstemp(suffix='yaml', dir=self.tempdir)
        os.close(fd)
        with open(f, 'wb') as fd:
            yaml.dump(thing, fd)

        return thing, f

    def test_load_config(self):
        thing, f = self._write_yaml()

        self.assertTrue(os.path.exists(f))
        self.assertTrue(os.path.getsize(f) > 0)

        loaded = certfuzz.config.simple_loader.load_config(f)

        self.assertTrue('config_timestamp' in loaded)
        self.assertEqual(os.path.getmtime(f), loaded.pop('config_timestamp'))

        self.assertEqual(thing, loaded)

    def test_empty_config(self):
        fd,fpath=tempfile.mkstemp(suffix='.yaml', prefix='empty_', dir=self.tempdir)
        os.close(fd)
        
        # make sure it exists and is empty
        self.assertTrue(os.path.exists(fpath))
        self.assertEqual(0,os.path.getsize(fpath))
        
        self.assertRaises(ConfigError,certfuzz.config.simple_loader.load_config,fpath)
    
    def test_nonexistent_config(self):
        fd,fpath=tempfile.mkstemp(suffix='.yaml', prefix='nonexistent_', dir=self.tempdir)
        os.close(fd)
        os.unlink(fpath)
        self.assertFalse(os.path.exists(fpath))
        
        self.assertRaises(IOError,certfuzz.config.simple_loader.load_config,fpath)
    
    def test_fix_config(self):
        cfgdict = MockCfg(templated=False)
        cfgdict2 = MockCfg(templated=False)
        
        # make sure cmdline_template is just a normal string
        self.assertEqual(type(''),type(cfgdict['target']['cmdline_template']))
        
        x = fixup_config(cfgdict)
        # fixup config should return a different dict

        # make sure cfgdict didn't change
        self.assertEqual(cfgdict,cfgdict2)

        # fixup_config should not alter cfgdict but return a new dict
        self.assertNotEqual(cfgdict,x)
        
        # make sure cmdline_template is a string.Template
        y = string.Template('foo')
        self.assertEqual(type(y),type(x['target']['cmdline_template']))

        self.assertTrue(x['target']['program'].endswith(cfgdict['target']['program']))


if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
