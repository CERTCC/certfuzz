'''
Created on Apr 10, 2012

@organization: cert.org
'''

import unittest
import tempfile
import shutil
import yaml
import os
from certfuzz.campaign import config
import pprint
from certfuzz.campaign.config.errors import ConfigError

_count = 0
def _counter():
    global _count
    _count += 1

class Test(unittest.TestCase):

    def setUp(self):
        self.tempdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tempdir)

    def _write_yaml(self, thing=None):
        if thing is None:
            thing = dict(a=1, b=2, c=3, d=4)
        fd, f = tempfile.mkstemp(suffix='yaml', dir=self.tempdir)
        os.close(fd)
        with open(f, 'wb') as fd:
            yaml.dump(thing, fd)

        return thing, f

    def test_parse_yaml(self):
        thing, f = self._write_yaml()

        self.assertTrue(os.path.exists(f))
        self.assertTrue(os.path.getsize(f) > 0)

        from_yaml = config.parse_yaml(f)
        self.assertEqual(thing, from_yaml)

    def test_config_init(self):
        thing, f = self._write_yaml()
        c = config.Config(f)
        self.assertEqual(f, c.file)
        self.assertEqual(thing, c.config)

    def test_validate(self):
        dummy, f = self._write_yaml()
        c = config.Config(f)
        # add some validations
        c.validations.append(_counter)
        c.validations.append(_counter)
        c.validations.append(_counter)

        # confirm that each validation got run
        self.assertEqual(0, _count)
        c.validate()
        self.assertEqual(3, _count)

    def test_init_fails_if_load_fails(self):
        dummy, f = self._write_yaml()
        os.remove(f)
        self.assertRaises(ConfigError, config.Config, f)

    def test_verify_load(self):
        # write another yaml file
        _thing, f = self._write_yaml()
        # sub the new file name
        c = config.Config(f)
        c.config = None
        self.assertRaises(ConfigError, c._verify_load)

    def test_load(self):
        # write another yaml file
        thing, f = self._write_yaml()
        # sub the new file name
        c = config.Config(f)
        # we should get the thing back again
        self.assertEqual(thing, c.config)

        # load should add each of the things as
        # config attributes
        for k, v in thing.iteritems():
            self.assertTrue(hasattr(c, k))
            self.assertEqual(c.__getattribute__(k), v)

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
