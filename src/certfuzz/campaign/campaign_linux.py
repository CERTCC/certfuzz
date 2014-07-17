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
from certfuzz.campaign.config import bff_config as cfg_helper
from certfuzz.campaign.errors import CampaignScriptError
from certfuzz.debuggers import crashwrangler  #@UnusedImport
from certfuzz.debuggers import gdb  #@UnusedImport
from certfuzz.debuggers.registration import verify_supported_platform
from certfuzz.file_handlers.tmp_reaper import TmpReaper
from certfuzz.fuzztools import subprocess_helper as subp
from certfuzz.fuzztools.process_killer import ProcessKiller
from certfuzz.fuzztools.state_timer import STATE_TIMER
from certfuzz.fuzztools.watchdog import WatchDog
from certfuzz.file_handlers.watchdog_file import TWDF, touch_watchdog_file
from certfuzz.fuzztools.ppid_observer import check_ppid
from certfuzz.iteration.iteration_linux import LinuxIteration


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
    def __init__(self, config_file=None, result_dir=None, debug=False):
        CampaignBase.__init__(self, config_file, result_dir, debug)

        # read configs
        logger.info('Reading config from %s', self.config_file)
        self.config = cfg_helper.read_config_options(self.config_file)

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

        # give up if we don't have a debugger
        verify_supported_platform()
        # give up if prog is a script
        self._check_for_script()

    def _pre_enter(self):
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
            pk.go()

    def _cache_app(self):
        logger.debug('cache program')
        sf = self.seedfile_set.next_item()

        # Run the program once to cache it into memory
        fullpathorig = self.config.full_path_original(sf.path)
        cmdargs = self.config.get_command_list(fullpathorig)
        subp.run_with_timer(cmdargs, self.config.progtimeout * 8, self.config.killprocname, use_shell=True)

        # Give target time to die
        time.sleep(1)

    def _setup_watchdog(self):
        logger.debug('setup watchdog')
        # setup our watchdog file toucher
        TWDF.remote_d = self.config.remote_dir
        TWDF.wdf = self.config.watchdogfile
        TWDF.enable()
        touch_watchdog_file()

        # set up the watchdog timeout within the VM and restart the daemon
        with WatchDog(self.config.watchdogfile, self.config.watchdogtimeout) as watchdog:
            watchdog.go()

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

    def _do_interval(self):
        # wipe the tmp dir clean to try to avoid filling the VM disk
        TmpReaper().clean_tmp()

        # choose seedfile
        sf = self.seedfile_set.next_item()
        logger.info('Selected seedfile: %s', sf.basename)

        r = sf.rangefinder.next_item()
        qf = not self.first_chunk

        logger.info(STATE_TIMER)

        interval_limit = self.current_seed + self.seed_interval

        # start an iteration interval
        # note that range does not include interval_limit
        logger.debug('Starting interval %d-%d', self.current_seed, interval_limit)
        for seednum in xrange(self.current_seed, interval_limit):
            self._do_iteration(sf, r, qf, seednum)

        self.current_seed = interval_limit
        self.first_chunk = False

    def _do_iteration(self, seedfile, range_obj, quiet_flag, seednum):
        # Prevent watchdog from rebooting VM.  If /tmp/fuzzing exists and is stale, the machine will reboot
        touch_watchdog_file()
        with LinuxIteration(cfg=self.config, seednum=seednum, seedfile=seedfile, r=range_obj, workdirbase=self.working_dir, quiet=quiet_flag,
            uniq_func=self._crash_is_unique,
            sf_set=self.seedfile_set,
            rf=seedfile.rangefinder,
            outdir=self.outdir) as iteration:
            iteration.go()
