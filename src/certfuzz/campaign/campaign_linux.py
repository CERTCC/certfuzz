'''
Created on Feb 12, 2014

@author: adh
'''

import logging
import os
import sys
import time
import traceback
import subprocess

from certfuzz.campaign.campaign_base import CampaignBase
from certfuzz.campaign.config import bff_config as cfg_helper
from certfuzz.campaign.errors import CampaignScriptError
from certfuzz.debuggers import crashwrangler  # @UnusedImport
from certfuzz.debuggers import gdb  # @UnusedImport
from certfuzz.debuggers.registration import verify_supported_platform
from certfuzz.file_handlers.tmp_reaper import TmpReaper
from certfuzz.fuzztools import subprocess_helper as subp
from certfuzz.fuzztools.process_killer import ProcessKiller
from certfuzz.fuzztools.state_timer import STATE_TIMER
from certfuzz.fuzztools.watchdog import WatchDog
from certfuzz.file_handlers.watchdog_file import TWDF, touch_watchdog_file
from certfuzz.fuzztools.ppid_observer import check_ppid
from certfuzz.iteration.iteration_linux import Iteration


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
    def __init__(self, config_file=None, result_dir=None, debug=False):
        # Read the cfg file
        self.config_file = config_file
        self.result_dir = result_dir
        self.debug = debug
        logger.info('Reading config from %s', self.config_file)
        self.cfg = cfg_helper.read_config_options(self.config_file)

        self.campaign_id = self.cfg.campaign_id
        self.current_seed = self.cfg.start_seed
        self.seed_interval = self.cfg.seed_interval

        self.seed_dir_in = self.cfg.seedfile_origin_dir

        self.outdir_base = os.path.abspath(self.cfg.output_dir)

        self.outdir = os.path.join(self.outdir_base, self.campaign_id)
        logger.debug('outdir=%s', self.outdir)
        self.sf_set_out = os.path.join(self.outdir, 'seedfiles')

        self.work_dir_base = self.cfg.local_dir

        self.program = self.cfg.program

        # flag to indicate whether this is a fresh script start up or not
        self.first_chunk = True

        self.seedfile_set = None

        self.hashes = []
        self.working_dir = None
        self.seed_dir_local = None
        self.crashes_seen = set()

        # give up if we don't have a debugger
        verify_supported_platform()

    def __enter__(self):
        self._start_process_killer()
        self._set_unbuffered_stdout()

        CampaignBase.__enter__(self)

        if self.cfg.watchdogtimeout:
            self._setup_watchdog()

        check_ppid()

        return self

    def __exit__(self, etype, value, mytraceback):
        handled = not etype

        if etype is KeyboardInterrupt:
            logger.warning('Keyboard interrupt - exiting')
            handled = True
        if etype is CampaignScriptError:
            logger.warning("Please configure BFF to fuzz a binary.  Exiting...")
            handled = True

        if handled:
            self._cleanup_workdir()
        elif self.debug:
            # Not handled, debug set

            # leave it behind if we're in debug mode
            # and there's a problem
            logger.debug('Skipping cleanup since we are in debug mode.')
        else:
            # Not handled, debug not set

            logger.debug('Unhandled exception:')
            logger.debug('  type: %s', etype)
            logger.debug('  value: %s', value)
            for l in traceback.format_exception(etype, value, mytraceback):
                logger.debug(l.rstrip())

        return handled

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
        with ProcessKiller(self.cfg.killprocname, self.cfg.killproctimeout) as pk:
            pk.go()

    def _cache_prg(self):
        logger.debug('cache program')
        sf = self.seedfile_set.next_item()

        # Run the program once to cache it into memory
        fullpathorig = self.cfg.full_path_original(sf.path)
        cmdargs = self.cfg.get_command_list(fullpathorig)
        subp.run_with_timer(cmdargs, self.cfg.progtimeout * 8, self.cfg.killprocname, use_shell=True)

        # Give target time to die
        time.sleep(1)

    def _setup_watchdog(self):
        logger.debug('setup watchdog')
        # setup our watchdog file toucher
        TWDF.remote_d = self.cfg.remote_dir
        TWDF.wdf = self.cfg.watchdogfile
        TWDF.enable()
        touch_watchdog_file()

        # set up the watchdog timeout within the VM and restart the daemon
        with WatchDog(self.cfg.watchdogfile, self.cfg.watchdogtimeout) as watchdog:
            watchdog.go()

    def _check_for_script(self):
        logger.debug('check for script')
        if check_program_file_type('text', self.program):
            logger.warning("Target application is a shell script.")
            raise CampaignScriptError()

    def _check_prog(self):
        self._check_for_script()
        CampaignBase._check_prog(self)

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
        logger.debug('Starting interval %d-%d', self.current_seed, interval_limit)
        for seednum in xrange(self.current_seed, interval_limit):
            self._do_iteration(sf, r, qf, seednum)

        self.current_seed = interval_limit
        self.first_chunk = False

    def _do_iteration(self, seedfile, range_obj, quiet_flag, seednum):
        # Prevent watchdog from rebooting VM.  If /tmp/fuzzing exists and is stale, the machine will reboot
        touch_watchdog_file()
        with Iteration(cfg=self.cfg, seednum=seednum, seedfile=seedfile, r=range_obj, workdirbase=self.working_dir, quiet=quiet_flag,
            uniq_func=self._crash_is_unique,
            sf_set=self.seedfile_set,
            rf=seedfile.rangefinder) as iteration:
            iteration.go()
