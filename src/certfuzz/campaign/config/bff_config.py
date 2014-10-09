'''
Created on Oct 19, 2010

@organization: cert.org
@contact: adh@cert.org

This module provides the ConfigHelper class to assist with converting a bff.cfg file into
a collection of attributes and methods to facilitate a fuzzing run.
'''
import ConfigParser
import logging
import os
import re
import shlex
import shutil

from certfuzz.fuzztools import filetools


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

UNIQ_LOG = "uniquelog.txt"
LAST_SEEDFILE = 'lastseed'

MINIMIZED_EXT = "minimal"
ZZUF_LOG_FILE = 'zzuf_log.txt'
RANGE_LOG = 'rangelog.txt'
CRASH_EXIT_CODE_FILE = "crashexitcodes"
CACHED_CONFIG_OBJECT_FILE = 'config.pkl'
CACHED_SEEDRANGE_OBJECT_FILE = 'seedrange.pkl'
CACHED_RANGEFINDER_OBJECT_FILE = 'rangefinder.pkl'
CACHED_SEEDFILESET_OBJECT_FILE = 'seedfile_set.pkl'
SEEDFILE_REPLACE_STRING = '\$SEEDFILE'


def read_config_options(cfg_file):
    '''
    Reads and parses <cfg_file>, returning a ConfigHelper object
    @rtype: ConfigHelper
    '''
    config = ConfigParser.ConfigParser()
    with open(cfg_file) as fp:
        config.readfp(fp)
    return ConfigHelper(config)


class ConfigHelper:
    '''ConfigHelper takes a generic ConfigParser raw object and provides the properties and
    helper methods necessary to configure a fuzz run.'''

    def __init__(self, cfg):
        '''Initialize a ConfigHelper object by passing in a ConfigParser object representing your bff.cfg file.

        @rtype: ConfigHelper'''
        self.cfg = cfg
        # [campaign]
        campaign_id = re.sub('\s+', '_', self.cfg.get('campaign', 'id'))
        self.campaign_id = campaign_id

        # [target]
        self.killprocname = os.path.basename(self.cfg.get('target', 'killprocname'))
        self.cmdline = self.cfg.get('target', 'cmdline')

        self.cmd_list = shlex.split(self.cmdline)
        for index, cmd_part in enumerate(self.cmd_list):
            self.cmd_list[index] = os.path.expanduser(cmd_part)
        if re.search(' ', self.cmd_list[0]):
            self.cmd_list[0] = '"' + self.cmd_list[0] + '"'
        self.program = self.cmd_list[0]
        self._cmd = self.cmd_list
        self._args = self.cmd_list[1:]

        # [timeouts]
        self.killproctimeout = self.cfg.getint('timeouts', 'killproctimeout')
        self.watchdogtimeout = self.cfg.getint('timeouts', 'watchdogtimeout')
        self.debugger_timeout = self.cfg.getfloat('timeouts', 'debugger_timeout')
        self.progtimeout = self.cfg.getfloat('timeouts', 'progtimeout')
        self.valgrindtimeout = self.cfg.getint('timeouts', 'valgrindtimeout')
        self.minimizertimeout = self.cfg.getint('timeouts', 'minimizertimeout')

        # [zzuf]
        self.copymode = self.cfg.getint('zzuf', 'copymode')
        self.start_seed = self.cfg.getint('zzuf', 'start_seed')
        self.seed_interval = self.cfg.getint('zzuf', 'seed_interval')

        # [verifier]
        self.backtracelevels = self.cfg.getint('verifier', 'backtracelevels')
        if self.cfg.has_option('verifier', 'exclude_unmapped_frames'):
            self.exclude_unmapped_frames = self.cfg.get('verifier', 'exclude_unmapped_frames')
        else:
            self.exclude_unmapped_frames = True
        self.minimizecrashers = self.cfg.getboolean('verifier', 'minimizecrashers')
        self.minimize_to_string = self.cfg.getboolean('verifier', 'minimize_to_string')
        if self.cfg.has_option('verifier', 'use_valgrind'):
            self.use_valgrind = self.cfg.getboolean('verifier', 'use_valgrind')
        else:
            self.use_valgrind = True
        if self.cfg.has_option('verifier', 'use_pin_calltrace'):
            self.use_pin_calltrace = self.cfg.getboolean('verifier', 'use_pin_calltrace')
        else:
            self.use_pin_calltrace = False
        if self.cfg.has_option('verifier', 'savefailedasserts'):
            self.savefailedasserts = self.cfg.getboolean('verifier', 'savefailedasserts')
        else:
            self.savefailedasserts = False
        if self.cfg.has_option('verifier', 'recycle_crashers'):
            self.recycle_crashers = self.cfg.getboolean('verifier', 'recycle_crashers')
        else:
            self.recycle_crashers = False
        if self.cfg.has_option('verifier', 'keep_duplicates'):
            self.keep_duplicates = self.cfg.getboolean('verifier', 'keep_duplicates')
        else:
            self.keep_duplicates = False

        # [directories]
        self.remote_dir = os.path.expanduser(self.cfg.get('directories', 'remote_dir'))
        self.seedfile_origin_dir = os.path.expanduser(self.cfg.get('directories', 'seedfile_origin_dir'))
        self.debugger_template_dir = os.path.expanduser(self.cfg.get('directories', 'debugger_template_dir'))
        self.local_dir = os.path.expanduser(self.cfg.get('directories', 'local_dir'))
        self.output_dir = os.path.expanduser(self.cfg.get('directories', 'output_dir'))

        self.watchdogfile = os.path.expanduser(self.cfg.get('directories', 'watchdog_file'))

        # derived properties
        self.program_basename = os.path.basename(self.program).replace('"', '')

        self.uniq_log = os.path.join(self.output_dir, UNIQ_LOG)

        self.crashexitcodesfile = os.path.join(self.local_dir, CRASH_EXIT_CODE_FILE)
        self.zzuf_log_file = os.path.join(self.local_dir, ZZUF_LOG_FILE)

        self.tmpdir = None

        # derived cached paths
#        self.cached_config_file = os.path.join(self.local_dir, CACHED_CONFIG_OBJECT_FILE)
#        self.cached_seedrange_file = os.path.join(self.local_dir, CACHED_SEEDRANGE_OBJECT_FILE)
#        self.cached_rangefinder_file = os.path.join(self.local_dir, CACHED_RANGEFINDER_OBJECT_FILE)
#        self.cached_seedfile_set = os.path.join(self.local_dir, CACHED_SEEDFILESET_OBJECT_FILE)

    def get_command(self, filepath):
        return ' '.join(self.get_command_list(filepath))

    def get_command_list(self, seedfile):
        cmdlst = [self.program]
        cmdlst.extend(self.get_command_args_list(seedfile))
        return cmdlst

    def get_command_args_list(self, seedfile):
        arglist = []
        for arg in self._args:
            arglist.append(re.sub(SEEDFILE_REPLACE_STRING, seedfile, arg))
        return arglist

    def zzuf_log_out(self, mydir):
        return os.path.join(mydir, ZZUF_LOG_FILE)

    def full_path_local_fuzz_dir(self, seedfile):
        '''
        Returns <local_dir>/<program_basename>/<seedfile>
        @param seedfile:
        '''
        return os.path.join(self.local_dir, self.program_basename, seedfile)

    def full_path_original(self, seedfile):
        '''
        Returns <full_path_local_fuzz_dir>/<seedfile>
        @param seedfile:
        '''
        return os.path.join(self.full_path_local_fuzz_dir(seedfile), seedfile)

    def get_minimized_file(self, outfile):
        '''
        @rtype: string
        @return: <outfile_root>-<MINIMIZED_EXT>.<outfile_ext>
        '''
        (head, tail) = os.path.split(outfile)
        (root, ext) = os.path.splitext(tail)
        new_filename = '%s-%s%s' % (root, MINIMIZED_EXT, ext)
        return os.path.join(head, new_filename)

    def get_filenames(self, outfile, use_minimized_as_root=True):
        '''
        @rtype: list
        @return: a list of filenames for minidump, stderr, gdb, valgrind, minimized
        '''
        minfile = self.get_minimized_file(outfile)
        if use_minimized_as_root:
            file_root = minfile
        else:
            file_root = outfile

        files = []
        for f in (self.get_minidump_file, self.get_stderr_file, self.get_gdb_file, self.get_valgrind_file):
            files.append(f(file_root))

        files.append(minfile)

        return files


    def create_tmpdir(self):
        # TODO: this should become part of campaign object
        if not self.tmpdir:
            self.tmpdir = filetools.mkdtemp(self.testscase_tmp_dir)
            logger.debug("Created temp dir %s", self.tmpdir)
        assert os.path.isdir(self.tmpdir)

    def clean_tmpdir(self):
        # TODO: this should become part of campaign object
        if self.tmpdir is None:
            return

        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir)
            logger.debug("Removed temp dir %s", self.tmpdir)
            assert not os.path.exists(self.tmpdir)
            self.tmpdir = None
        self.create_tmpdir()

    def get_testcase_outfile(self, seedfile, s1):
        # TODO: this should become part of campaign object
        '''
        @rtype: string
        @return: the path to the output file for this seed: <self.fullpathoriginal>.<s1>
        '''
        (dirname, basename) = os.path.split(seedfile)  # @UnusedVariable
        (root, ext) = os.path.splitext(basename)
        new_root = '%s-%d' % (root, s1)
        new_basename = '%s%s' % (new_root, ext)
        self.create_tmpdir()
        return os.path.join(self.tmpdir, new_basename)
