'''
Created on Apr 10, 2012

@organization: cert.org
'''

import os
import pprint
import shutil
import tempfile
import unittest

import yaml

import certfuzz.config.config_base as config
from certfuzz.config.errors import ConfigError


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
            thing = dict([(y, x) for x, y in enumerate("abcd")])
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
        _junk, f = self._write_yaml()
        c = config.ConfigBase(f)
        self.assertEqual(f, c.file)

    def test_validate(self):
        dummy, f = self._write_yaml()
        c = config.ConfigBase(f)
        # add some validations
        c.validations.append(_counter)
        c.validations.append(_counter)
        c.validations.append(_counter)

        # confirm that each validation got run
        self.assertEqual(0, _count)
        c.validate()
        self.assertEqual(3, _count)

    def test_load(self):
        # write another yaml file
        thing, f = self._write_yaml()
        # sub the new file name
        with config.ConfigBase(f) as c:
            # we should get the thing back again
            self.assertEqual(thing, c.config)

        # load should add each of the things as
        # config attributes
        for k, v in thing.iteritems():
            self.assertTrue(hasattr(c, k))
            self.assertEqual(c.__getattribute__(k), v)

    def test_set_derived_options(self):
        c = config.ConfigBase('foo')
        self.assertEqual(None, c.config)
        self.assertRaises(ConfigError, c._set_derived_options)

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
