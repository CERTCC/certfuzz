'''
Created on Nov 11, 2014

@author: adh
'''
import os
from pprint import pprint
import shutil
import tempfile
import unittest

import yaml

from certfuzz.config.config_linux import LinuxConfig, MINIMIZED_EXT
import certfuzz.config.config_linux as cl
from certfuzz.config.errors import ConfigError


CFG = '''
campaign:
    id: convert v5.2.0
target:
    cmdline: ~/convert $SEEDFILE /dev/null
    killprocname: convert
directories:
    remote_dir: ~/bff &remote_dir
    seedfile_origin_dir: ~/bff/seedfiles/examples
    debugger_template_dir: ~/bff/certfuzz/debuggers/templates
    output_dir: ~/results
    local_dir: ~/fuzzing
    watchdog_file: /tmp/bff_watchdog
zzuf:
    copymode: 1
    start_seed: 0
    seed_interval: 20
verifier:
    backtracelevels: 5
    exclude_unmapped_frames: True
    savefailedasserts: False
    use_valgrind: True
    use_pin_calltrace: False
    minimizecrashers: True
    minimize_to_string: False
    recycle_crashers: False
timeouts:
    progtimeout: 5
    killproctimeout: 130
    debugger_timeout: 60
    valgrindtimeout: 120
    watchdogtimeout: 3600
    minimizertimeout: 3600
'''

class Test(unittest.TestCase):

    def setUp(self):
        self.c = yaml.load(CFG)
        self.tmpdir = tempfile.mkdtemp()
        fd, self.yamlfile = tempfile.mkstemp(suffix='.yaml', dir=self.tmpdir, text=True)
        os.close(fd)
        with open(self.yamlfile, 'w') as stream:
            yaml.dump(self.c, stream)
            
        self.cfg = LinuxConfig(self.yamlfile)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_init(self):
        self.assertEqual(self.yamlfile, self.cfg.file)
        self.assertEqual(None, self.cfg.config)
        self.assertEqual(None, self.cfg.configdate)
        for key in self.c.iterkeys():
            self.assertFalse(hasattr(self.cfg, key))

    def test_contextmgr(self):
        # expect to throw an error if the file doesn't exist
        bogusfile = os.path.join(self.tmpdir, 'nonexistent_file')
        cfg = LinuxConfig(bogusfile)
        self.assertRaises(ConfigError, cfg.__enter__)

        with self.cfg:
            self.assertNotEqual(None, self.cfg.config)
            self.assertEqual(dict, type(self.cfg.config))
            self.assertNotEqual(None, self.cfg.configdate)
            for key in self.c.iterkeys():
                self.assertTrue(hasattr(self.cfg, key))

    def test_set_derived_options(self):
        with self.cfg:
            for blockname, dtypes in cl._DTYPES.iteritems():
                for k, dtype in dtypes.iteritems():
                    self.assertTrue(hasattr(self.cfg, k))
                    attr_val = getattr(self.cfg, k)
                    self.assertEqual(dtype, type(attr_val))
                    if blockname == 'directories':
                        continue
                    self.assertEqual(self.c[blockname][k], attr_val)
            self.assertTrue(self.cfg.uniq_log.endswith(cl.UNIQ_LOG))
            self.assertTrue(self.cfg.crashexitcodesfile.endswith(cl.CRASH_EXIT_CODE_FILE))
            self.assertTrue(self.cfg.zzuf_log_file.endswith(cl.ZZUF_LOG_FILE))
            self.assertEqual(self.cfg.zzuf_log_out('seedfile'), os.path.join('seedfile', 'zzuf_log.txt'))

    def test_get_command(self):
        with self.cfg:
            self.assertIn('foo', self.cfg.get_command('foo'))

    def test_get_command_list(self):
        with self.cfg:
            result = self.cfg.get_command_list('foo')
            self.assertTrue(result[0].endswith('convert'))
            self.assertEqual(result[1], 'foo')
            self.assertEqual(result[2], '/dev/null')

    def test_get_command_args_list(self):
        with self.cfg:
            result = self.cfg.get_command_args_list('foo')
            self.assertEqual(result[0], 'foo')
            self.assertEqual(result[1], '/dev/null')

    def test_zzuf_log_out(self):
        with self.cfg:
            result = self.cfg.zzuf_log_out('foo')
            self.assertEqual(str, type(result))
            self.assertTrue(result.startswith('foo'))
            self.assertTrue(result.endswith(cl.ZZUF_LOG_FILE))

    def test_full_path_local_fuzz_dir(self):
        with self.cfg:
            result = self.cfg.full_path_local_fuzz_dir('foo')
            self.assertEqual(str, type(result))
            self.assertTrue(result.endswith('foo'))

    def test_full_path_original(self):
        with self.cfg:
            result = self.cfg.full_path_original('foo')
            self.assertEqual(str, type(result))
            self.assertTrue(result.endswith(os.path.join('foo', 'foo')))

    def test_get_minimized_file(self):
        with self.cfg:
            self.assertEqual(self.cfg.get_minimized_file('foo.txt'), 'foo-%s.txt' % MINIMIZED_EXT)

    def test_get_filenames(self):
        with self.cfg:
            result = self.cfg.get_filenames('foo.bar.baz', use_minimized_as_root=True)

            print result
            result = self.cfg.get_filenames('foo.bar.baz', use_minimized_as_root=False)
            print result
if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
