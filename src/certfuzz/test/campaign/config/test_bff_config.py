'''
Created on Apr 8, 2011

@organization: cert.org
'''
import unittest
import os
import ConfigParser
from certfuzz.campaign.config.bff_config import ConfigHelper
from certfuzz.campaign.config.bff_config import MINIMIZED_EXT
from certfuzz.campaign.config.bff_config import KILL_SCRIPT
import tempfile
from certfuzz.campaign.config.bff_config import read_config_options

class Test(unittest.TestCase):
    def delete_file(self, f):
        os.remove(f)
        self.assertFalse(os.path.exists(f))

    def setUp(self):
        # build a config
        self.config = ConfigParser.RawConfigParser()

        self.config.add_section("campaign")
        self.config.set('campaign', 'id', 'campaign_id')
        self.config.set('campaign', 'distributed', 'False')

        self.config.add_section("directories")
        self.config.set('directories', 'remote_dir', 'remote_dir')
        self.config.set('directories', 'crashers_dir', 'crashers_dir')
        self.config.set('directories', 'seedfile_origin_dir', 'seedfile_origin_dir')

        self.config.set('directories', 'output_dir', 'output_dir')
        self.config.set('directories', 'local_dir', 'local_dir')
        self.config.set('directories', 'seedfile_output_dir', 'seedfile_output_dir')
        self.config.set('directories', 'seedfile_local_dir', 'seedfile_local_dir')
        self.config.set('directories', 'cached_objects_dir', 'cached_objects_dir')
        self.config.set('directories', 'temp_working_dir', 'temp_working_dir')
        self.config.set('directories', 'watchdog_file', 'watchdog_file')
        self.config.set('directories', 'debugger_template_dir', 'debugger_template_dir')

        self.config.add_section("target")
        self.config.set('target', 'cmdline', '/path/to/program $SEEDFILE outfile.ext')
        self.config.set('target', 'killprocname', '/path/to/killprocname')

        self.config.add_section('timeouts')
        self.config.set('timeouts', 'killproctimeout', '1')
        self.config.set('timeouts', 'watchdogtimeout', '2')
        self.config.set('timeouts', 'debugger_timeout', '4')
        self.config.set('timeouts', 'progtimeout', '3.4')
        self.config.set('timeouts', 'valgrindtimeout', '6')
        self.config.set('timeouts', 'minimizertimeout', '6')

        self.config.add_section('zzuf')
        self.config.set('zzuf', 'copymode', '1')
        self.config.set('zzuf', 'ratiomin', '0.0001')
        self.config.set('zzuf', 'ratiomax', '0.01')
        self.config.set('zzuf', 'start_seed', '1000')
        self.config.set('zzuf', 'seed_interval', '500')
        self.config.set('zzuf', 'max_seed', '100000')

        self.config.add_section('verifier')
        self.config.set('verifier', 'backtracelevels', '17')
        self.config.set('verifier', 'minimizecrashers', '1')
        self.config.set('verifier', 'manualcutoff', '10')
#        self.config.set('verifier', 'keepduplicates', '1')
        self.config.set('verifier', 'minimize_to_string', '1')
        self.config.set('verifier', 'use_valgrind', '1')

        # create a ConfigHelper object
        self.cfg = ConfigHelper(self.config)

    def tearDown(self):
        pass

    def test_init(self):
        self.assertEqual(self.cfg.killprocname, 'killprocname')
        self.assertEqual(self.cfg.killproctimeout, 1)
        self.assertEqual(self.cfg.watchdogtimeout, 2)
        self.assertEqual(self.cfg.copymode, 1)
        self.assertEqual(self.cfg.progtimeout, 3.4)
        self.assertEqual(self.cfg.seedfile_local_dir, 'seedfile_local_dir')
        self.assertEqual(self.cfg.output_dir, 'output_dir')
        self.assertEqual(self.cfg.local_dir, 'local_dir')
        self.assertEqual(self.cfg.debugger_timeout, 4)
        self.assertEqual(self.cfg.backtracelevels, 17)
        self.assertEqual(self.cfg.minimizecrashers, 1)
        self.assertEqual(self.cfg.valgrindtimeout, 6)

    def test_program_is_script(self):
        pass

    def test_check_program_file_type(self):
        f = os.path.abspath(__file__)
        if f.endswith('pyc'):
            # trim the last char ('c')
            f = f[:-1]
        self.cfg.program = f
        print f
        self.assertTrue(self.cfg.program_is_script())

    def test_get_minimized_file(self):
        self.assertEqual(self.cfg.get_minimized_file('foo.txt'), 'foo-%s.txt' % MINIMIZED_EXT)

    def test_get_killscript_path(self):
        self.assertEqual(self.cfg.get_killscript_path('foo'), os.path.join('foo', '%s') % KILL_SCRIPT)

    def test_uniquelog(self):
        self.assertEqual(self.cfg.uniq_log, os.path.join('output_dir', 'uniquelog.txt'))

    def test_crashexitcodesfile(self):
        self.assertEqual(self.cfg.crashexitcodesfile, os.path.join('local_dir', 'crashexitcodes'))

    def test_zzuf_log_file(self):
        self.assertEqual(self.cfg.zzuf_log_file, os.path.join('local_dir', 'zzuf_log.txt'))

    def test_zzuf_log_out(self):
        self.assertEqual(self.cfg.zzuf_log_out('seedfile'), os.path.join('seedfile', 'zzuf_log.txt'))

    def test_read_config_options(self):
        (fd, f) = tempfile.mkstemp(text=True)
        os.close(fd)

        with open(f, 'wb') as configfile:
            self.config.write(configfile)

        cfg = read_config_options(f)

        self.assertEqual(cfg.killprocname, 'killprocname')
        self.assertEqual(cfg.killproctimeout, 1)
        self.assertEqual(cfg.watchdogtimeout, 2)
        self.assertEqual(cfg.copymode, 1)
        self.assertEqual(cfg.progtimeout, 3.4)
        self.assertEqual(cfg.seedfile_local_dir, 'seedfile_local_dir')
        self.assertEqual(cfg.output_dir, 'output_dir')
        self.assertEqual(cfg.local_dir, 'local_dir')
        self.assertEqual(cfg.debugger_timeout, 4)
        self.assertEqual(cfg.backtracelevels, 17)
        self.assertEqual(cfg.minimizecrashers, 1)
        self.assertEqual(cfg.valgrindtimeout, 6)

        self.delete_file(f)

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
