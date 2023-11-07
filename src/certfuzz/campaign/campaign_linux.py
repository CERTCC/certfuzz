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
from certfuzz.campaign.errors import CampaignScriptError, CmdlineTemplateError
from certfuzz.debuggers import crashwrangler  # @UnusedImport
from certfuzz.debuggers import gdb  # @UnusedImport
from certfuzz.file_handlers.watchdog_file import TWDF, touch_watchdog_file
from certfuzz.fuzztools import subprocess_helper as subp
from certfuzz.fuzztools import hostinfo
from certfuzz.fuzztools.ppid_observer import check_ppid
from certfuzz.fuzztools.watchdog import WatchDog
from certfuzz.iteration.iteration_linux import LinuxIteration
from certfuzz.fuzztools.command_line_templating import get_command_args_list
from certfuzz.fuzzers.errors import FuzzerExhaustedError


logger = logging.getLogger(__name__)
host_info = hostinfo.HostInfo()

SEEDFILE_REPLACE_STRING = '\$SEEDFILE'


def check_program_file_type(string, program):
    '''
    @rtype: boolean
    Runs the system "file" command on self.program
    @return: True if <string> appears in the output.
    '''
    file_loc = subprocess.Popen(
        "which %s" % program, stdout=subprocess.PIPE, shell=True).stdout.read().strip()
    # maybe it's not on the path, but it still exists
    if not file_loc:
        if os.path.exists(program):
            file_loc = program

    # we still can't find it, so give give up
    if not os.path.exists(file_loc):
        return False

    # get the 'file' results
    ftype = subprocess.Popen(
        "file -b -L %s" % file_loc, stdout=subprocess.PIPE, shell=True).stdout.read()
    if string in ftype:
        return True
    else:
        return False


class LinuxCampaign(CampaignBase):
    '''
    Extends CampaignBase to add linux-specific features.
    '''

    def __init__(self, config_file, result_dir=None, debug=False):
        CampaignBase.__init__(self, config_file, result_dir, debug)
        self.runner_module_name = 'certfuzz.runners.zzufrun'
        self.debugger_module_name = 'certfuzz.debuggers.gdb'
        # Assume gdb compatible with CERT Triage Tools
        self.config['debugger']['ctt_compat'] = True
        # Assume we're on Linux, which has /proc
        self.config['debugger']['proc_compat'] = True

    def _full_path_original(self, seedfile):
        # yes, two seedfile mentions are intended - adh
        program_basename = os.path.basename(self.program).replace('"', '')
        return os.path.join(self.work_dir_base,
                            program_basename,
                            seedfile,
                            seedfile)

#     def _get_command_list(self, seedfile):
# return [re.sub(SEEDFILE_REPLACE_STRING, seedfile, item) for item in
# self.cmd_list]

    def _pre_enter(self):
        # give up if prog is a script
        self._check_for_script()
        self._set_unbuffered_stdout()
        self._setup_environment()
        if not host_info.is_osx():
            # OSX doesn't use gdb,
            self._check_gdb_compat()

    def _post_enter(self):
        if self.config['runoptions']['watchdogtimeout']:
            self._setup_watchdog()
        check_ppid()
        self._cache_app()

    def _pre_exit(self):
        TWDF.remove_wdf()

    def _set_unbuffered_stdout(self):
        '''
        Reopens stdout with a buffersize of 0 (unbuffered)
        @rtype: none
        '''
        logger.debug('set unbuffered stdout')
        # reopen stdout file descriptor with write mode
        # and 0 as the buffer size (unbuffered)
        sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)

    def _cache_app(self):
        logger.debug('cache program')
        sf = self.seedfile_set.next_item()

        # Run the program once to cache it into memory
        fullpathorig = self._full_path_original(sf.path)
        cmdargs = get_command_args_list(
            self.config['target']['cmdline_template'], infile=fullpathorig)[1]

        if 'copyfuzzedto' in self.config['target']:
            from shutil import copyfile
            copyfuzzedto = str(self.config['target'].get('copyfuzzedto', ''))
            logger.debug("Copying seed file to " + copyfuzzedto)
            copyfile(fullpathorig, copyfuzzedto)

        if 'postprocessfuzzed' in self.config['target']:
            postprocessfuzzed = str(self.config['target']['postprocessfuzzed'])
            logger.debug("Executing postprocess " + postprocessfuzzed)
            os.system(postprocessfuzzed)

        logger.info('Invoking %s' % cmdargs)
        subp.run_with_timer(cmdargs,
                            self.config['runner']['runtimeout'] * 8,
                            self.config['target']['program'],
                            use_shell=False,
                            seeoutput=True,
                            )

        # Give target time to die
        logger.info(
            'Please ensure that the target program has just executed successfully')
        time.sleep(10)

    def _setup_watchdog(self):
        # short circuit if we're not using the watchdog
        if not TWDF.use_watchdog:
            logger.debug('skipping watchdog setup')
            return

        logger.debug('setup watchdog')
        # setup our watchdog file toucher
        touch_watchdog_file()

        # set up the watchdog timeout within the VM and restart the daemon
        with WatchDog(TWDF.wdf, self.config['runoptions']['watchdogtimeout']) as watchdog:
            watchdog()

    def _setup_environment(self):
        os.environ['KDE_DEBUG'] = '1'

    def _check_gdb_compat(self):
        logger.debug('checking /proc compatibility')
        if not host_info.is_linux():
            logger.debug(
                'Current platform does not support /proc. Adjusting debugger templates.')
            self.config['debugger']['proc_compat'] = False

        logger.debug('checking CERT Triage Tool compatibility')
        gdb_version = subprocess.check_output(['gdb', '--version'])
        if 'gdb 6' in gdb_version:
            self.config['debugger']['ctt_compat'] = False
            return
        current_dir = os.path.dirname(__file__)
        ctt_path = os.path.join(
            current_dir, '..', '..', 'CERT_triage_tools', 'exploitable', 'exploitable.py')
        gdb_output = subprocess.check_output([
            'gdb', '-ex', 'source %s' % ctt_path, '-ex', 'q'], stderr=subprocess.STDOUT)
        if 'Error: ' in gdb_output:
            logger.warning(
                'gdb is not compatible with CERT Triage Tools (older than 7.2?). Disabling.')
            self.config['debugger']['ctt_compat'] = False

    def _check_for_script(self):
        logger.debug('check for script')
        if check_program_file_type('text', self.program):
            logger.warning("Target application is a shell script.")
            raise CampaignScriptError()

    def _set_debugger(self):
        '''
        Overrides parent class
        '''
        pass

    def _do_iteration(self, seedfile, range_obj, seednum):
        # Prevent watchdog from rebooting VM.
        # If /tmp/fuzzing exists and is stale, the machine will reboot
        touch_watchdog_file()
        with LinuxIteration(seedfile=seedfile,
                            seednum=seednum,
                            workdirbase=self.working_dir,
                            outdir=self.outdir,
                            sf_set=self.seedfile_set,
                            uniq_func=self._testcase_is_unique,
                            config=self.config,
                            fuzzer_cls=self.fuzzer_cls,
                            runner_cls=self.runner_cls,
                            ) as iteration:
            try:
                iteration()
            except FuzzerExhaustedError:
                # Some fuzzers run out of things to do. They should
                # raise a FuzzerExhaustedError when that happens.
                logger.info(
                    'Done with %s, removing from set', seedfile.basename)
                self.seedfile_set.remove_file(seedfile)
