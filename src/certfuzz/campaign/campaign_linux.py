'''
Created on Feb 12, 2014

@author: adh
'''

import logging
import os
import subprocess
import sys
import time

from certfuzz.campaign.campaign_base import CampaignBase
from certfuzz.campaign.errors import CampaignScriptError
from certfuzz.debuggers import crashwrangler  # @UnusedImport
from certfuzz.debuggers import gdb  # @UnusedImport
from certfuzz.file_handlers.watchdog_file import TWDF, touch_watchdog_file
from certfuzz.fuzztools import subprocess_helper as subp
from certfuzz.fuzztools.ppid_observer import check_ppid
from certfuzz.fuzztools.process_killer import ProcessKiller
from certfuzz.fuzztools.watchdog import WatchDog
from certfuzz.iteration.iteration_linux import LinuxIteration
from certfuzz.fuzzers.bytemut import ByteMutFuzzer
from certfuzz.runners.zzufrun import ZzufRunner
from certfuzz.helpers.misc import fixup_path
from certfuzz.fuzztools.command_line_templating import get_command_args_list


logger = logging.getLogger(__name__)


SEEDFILE_REPLACE_STRING = '\$SEEDFILE'


def check_program_file_type(string, program):
    '''
    @rtype: boolean
    Runs the system "file" command on self.program
    @return: True if <string> appears in the output.
    '''
    file_loc = subprocess.Popen("which %s" % program, stdout=subprocess.PIPE, shell=True).stdout.read().strip()
    # maybe it's not on the path, but it still exists
    if not file_loc:
        if os.path.exists(program):
            file_loc = program

    # we still can't find it, so give give up
    if not os.path.exists(file_loc):
        return False

    # get the 'file' results
    ftype = subprocess.Popen("file -b -L %s" % file_loc, stdout=subprocess.PIPE, shell=True).stdout.read()
    if string in ftype:
        return True
    else:
        return False

class LinuxCampaign(CampaignBase):
    '''
    Extends CampaignBase to add linux-specific features.
    '''
    def __init__(self, config_file=None, result_dir=None, debug=False):
        CampaignBase.__init__(self, config_file, result_dir, debug)

        # pull stuff out of configs
        self.campaign_id = self.config['campaign']['id']
        self.current_seed = self.config['runoptions']['start_seed']
        self.seed_interval = self.config['runoptions']['seed_interval']
        self.seed_dir_in = fixup_path(self.config['directories']['seedfile_origin_dir'])

        if self.outdir_base is None:
            # it wasn't spec'ed on the command line so use the config
            self.outdir_base = fixup_path(self.config['directories']['output_dir'])

        self.work_dir_base = fixup_path(self.config['directories']['local_dir'])
        self.program = fixup_path(self.config['target']['program'])
        self.program_basename = os.path.basename(self.program).replace('"', '')
#         self.cmd_list = shlex.split(self.config['target']['cmdline'])
#         self.cmd_list[0] = fixup_path(self.cmd_list[0])


        # must occur after work_dir_base, outdir_base, and campaign_id are set
        self._common_init()

    def _full_path_original(self, seedfile):
        # yes, two seedfile mentions are intended - adh
        return os.path.join(self.work_dir_base,
                            self.program_basename,
                            seedfile,
                            seedfile)

#     def _get_command_list(self, seedfile):
#         return [re.sub(SEEDFILE_REPLACE_STRING, seedfile, item) for item in self.cmd_list]

    def _pre_enter(self):
        # give up if prog is a script
        self._check_for_script()

        self._start_process_killer()
        self._set_unbuffered_stdout()
        self._check_for_script()

    def _post_enter(self):
        if self.config['runoptions']['watchdogtimeout']:
            self._setup_watchdog()
        check_ppid()
        self._cache_app()

    def _pre_exit(self):
        pass

    def _set_unbuffered_stdout(self):
        '''
        Reopens stdout with a buffersize of 0 (unbuffered)
        @rtype: none
        '''
        logger.debug('set unbuffered stdout')
        # reopen stdout file descriptor with write mode
        # and 0 as the buffer size (unbuffered)
        sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)

    def _start_process_killer(self):
        logger.debug('start process killer')
        with ProcessKiller(self.config['target']['killprocname'],
                           self.config['runoptions']['killproctimeout']
                           ) as pk:
            self.pk_pid = pk.go()

    def _cache_app(self):
        logger.debug('cache program')
        sf = self.seedfile_set.next_item()

        # Run the program once to cache it into memory
        fullpathorig = self._full_path_original(sf.path)
        cmdargs = get_command_args_list(self.config['target']['cmdline_template'], infile=fullpathorig)[1]
        subp.run_with_timer(cmdargs,
                            self.config['runner']['runtimeout'] * 8,
                            self.config['target']['killprocname'],
                            use_shell=False)

        # Give target time to die
        time.sleep(1)

    def _setup_watchdog(self):
        logger.debug('setup watchdog')
        # setup our watchdog file toucher
        wdf = self.config['directories']['watchdog_file']

        TWDF.wdf = wdf
        TWDF.enable()
        touch_watchdog_file()

        # set up the watchdog timeout within the VM and restart the daemon
        with WatchDog(wdf, self.config['timeouts']['watchdogtimeout']) as watchdog:
            watchdog()

    def _check_for_script(self):
        logger.debug('check for script')
        if check_program_file_type('text', self.program):
            logger.warning("Target application is a shell script.")
            raise CampaignScriptError()

    def _set_fuzzer(self):
        '''
        Overrides parent class
        '''
        pass

    def _set_runner(self):
        '''
        Overrides parent class
        '''
        pass

    def _set_debugger(self):
        '''
        Overrides parent class
        '''
        pass

    def __setstate__(self):
        '''
        Overrides parent class
        '''
        pass

    def _read_state(self):
        '''
        Overrides parent class
        '''
        pass

    def __getstate__(self):
        '''
        Overrides parent class
        '''
        pass

    def _save_state(self):
        '''
        Overrides parent class
        '''
        pass

    def _do_iteration(self, seedfile, range_obj, seednum):
        # Prevent watchdog from rebooting VM.  If /tmp/fuzzing exists and is stale, the machine will reboot
        touch_watchdog_file()
        with LinuxIteration(seedfile=seedfile,
                            seednum=seednum,
                            workdirbase=self.working_dir,
                            outdir=self.outdir,
                            sf_set=self.seedfile_set,
                            uniq_func=self._crash_is_unique,
                            cfg=self.config,
                            fuzzer_cls=ByteMutFuzzer,
                            runner_cls=ZzufRunner,
                            ) as iteration:
            iteration()
