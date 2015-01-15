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
from certfuzz.config.config_linux import LinuxConfig
from certfuzz.debuggers import crashwrangler  # @UnusedImport
from certfuzz.debuggers import gdb  # @UnusedImport
from certfuzz.file_handlers.watchdog_file import TWDF, touch_watchdog_file
from certfuzz.fuzztools import subprocess_helper as subp
from certfuzz.fuzztools.ppid_observer import check_ppid
from certfuzz.fuzztools.process_killer import ProcessKiller
from certfuzz.fuzztools.watchdog import WatchDog
from certfuzz.iteration.iteration_linux import LinuxIteration
from certfuzz.fuzzers.zzuf import ZzufFuzzer
from certfuzz.fuzzers.bytemut import ByteMutFuzzer
from certfuzz.runners.zzufrun import ZzufRunner


logger = logging.getLogger(__name__)


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
    _config_cls = LinuxConfig

    def __init__(self, config_file=None, result_dir=None, debug=False):
        CampaignBase.__init__(self, config_file, result_dir, debug)

        # pull stuff out of configs
        self.campaign_id = self.config.campaign_id
        self.current_seed = self.config.start_seed
        self.seed_interval = self.config.seed_interval
        self.seed_dir_in = self.config.seedfile_origin_dir

        if self.outdir_base is None:
            # it wasn't spec'ed on the command line so use the config
            self.outdir_base = os.path.abspath(self.config.output_dir)

        self.work_dir_base = self.config.local_dir
        self.program = self.config.program

        # must occur after work_dir_base, outdir_base, and campaign_id are set
        self._common_init()


    def _read_config_file(self):
        CampaignBase._read_config_file(self)

        with self._config_cls(self.config_file) as cfgobj:
            self.config = cfgobj
            self.configdate = cfgobj.configdate

    def _pre_enter(self):
        # give up if prog is a script
        self._check_for_script()

        self._start_process_killer()
        self._set_unbuffered_stdout()
        self._check_for_script()

    def _post_enter(self):
        if self.config.watchdogtimeout:
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
        with ProcessKiller(self.config.killprocname, self.config.killproctimeout) as pk:
            self.pk_pid = pk.go()

    def _cache_app(self):
        logger.debug('cache program')
        sf = self.seedfile_set.next_item()

        # Run the program once to cache it into memory
        fullpathorig = self.config.full_path_original(sf.path)
        cmdargs = self.config.get_command_list(fullpathorig)
        subp.run_with_timer(cmdargs, self.config.progtimeout * 8, self.config.killprocname, use_shell=False)

        # Give target time to die
        time.sleep(1)

    def _setup_watchdog(self):
        logger.debug('setup watchdog')
        # setup our watchdog file toucher
        TWDF.wdf = self.config.watchdogfile
        TWDF.enable()
        touch_watchdog_file()

        # set up the watchdog timeout within the VM and restart the daemon
        with WatchDog(self.config.watchdogfile, self.config.watchdogtimeout) as watchdog:
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
