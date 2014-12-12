'''
Created on Oct 30, 2014

@organization: cert.org
'''
from functools import partial
import logging
import os
import re
import shlex
import shutil

from certfuzz.config.config_base import ConfigBase
from certfuzz.fuzztools import filetools
from certfuzz.helpers.misc import quoted


logger = logging.getLogger(__name__)

_DTYPES = {'timeouts': {'killproctimeout': int,
                        'watchdogtimeout': int,
                        'debugger_timeout': float,
                        'progtimeout': float,
                        'valgrindtimeout': int,
                        'minimizertimeout': int,
                        },
           'zzuf': {'copymode': bool,
                    'start_seed': int,
                    'seed_interval': int,
                    },
           'verifier': {'backtracelevels': int,
                        'keep_duplicates': bool,
                        'exclude_unmapped_frames': bool,
                        'minimizecrashers': bool,
                        'minimize_to_string': bool,
                        'use_valgrind': bool,
                        'use_pin_calltrace': bool,
                        'savefailedasserts': bool,
                        'recycle_crashers': bool,
                        },
           'directories': {'remote_dir': str,
                           'seedfile_origin_dir': str,
                           'debugger_template_dir': str,
                           'local_dir': str,
                           'output_dir': str,
                           'watchdog_file': str,
                           },
           'target': {
                      'killprocname': str,
                      'cmdline': str,
                      }
           }

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

class LinuxConfig(ConfigBase):
    '''
    Defines a linux-specific configuration file format
    '''
    def _set_derived_options(self):
        ConfigBase._set_derived_options(self)

        # [campaign]
        campaign_id = re.sub('\s+', '_', self.config['campaign']['id'])
        self.campaign_id = campaign_id

        # unroll ~ & relative paths
        dir_dict = self.config['directories']
        for k, path in dir_dict.iteritems():
            dir_dict[k] = os.path.abspath(os.path.expanduser(path))

        # cast the data to the expected type
        for k, dtypes in _DTYPES.iteritems():
            # pick the top-level config block to work with
            cfgblock = self.config[k]
            for key, dtype in dtypes.iteritems():
                # get the value if it's present
                # otherwise take the default type value (e.g., int() = 0, str() = '')
                val = cfgblock.get(key, dtype())
                # set the attribute, casting it to the expected type
                setattr(self, key, dtype(val))

        self.cmd_list = shlex.split(self.cmdline)
        for index, cmd_part in enumerate(self.cmd_list):
            self.cmd_list[index] = os.path.expanduser(cmd_part)
        if re.search(' ', self.cmd_list[0]):
            self.cmd_list[0] = quoted(self.cmd_list[0])
        self.program = self.cmd_list[0]
        self._cmd = self.cmd_list
        self._args = self.cmd_list[1:]

        # for backwards compatibility
        self.watchdogfile = self.watchdog_file

        # derived properties
        self.program_basename = os.path.basename(self.program).replace('"', '')
        self.uniq_log = os.path.join(self.output_dir, UNIQ_LOG)
        self.crashexitcodesfile = os.path.join(self.local_dir, CRASH_EXIT_CODE_FILE)
        self.zzuf_log_file = os.path.join(self.local_dir, ZZUF_LOG_FILE)

        # derived cached paths
#        self.cached_config_file = os.path.join(self.local_dir, CACHED_CONFIG_OBJECT_FILE)
#        self.cached_seedrange_file = os.path.join(self.local_dir, CACHED_SEEDRANGE_OBJECT_FILE)
#        self.cached_rangefinder_file = os.path.join(self.local_dir, CACHED_RANGEFINDER_OBJECT_FILE)
#        self.cached_seedfile_set = os.path.join(self.local_dir, CACHED_SEEDFILESET_OBJECT_FILE)


#         self.tmpdir = None

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


