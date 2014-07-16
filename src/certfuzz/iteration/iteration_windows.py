'''
Created on Mar 2, 2012

@author: adh
'''
import glob
import logging
import os
import shutil
import string
import tempfile

from certfuzz import debuggers
from certfuzz.campaign.config.config_windows import get_command_args_list
from certfuzz.crash.crash_windows import WindowsCrash
from certfuzz.debuggers.output_parsers import DebuggerFileError
from certfuzz.file_handlers.basicfile import BasicFile
from certfuzz.file_handlers.tmp_reaper import TmpReaper
from certfuzz.fuzzers.errors import FuzzerError, FuzzerExhaustedError, \
    FuzzerInputMatchesOutputError
from certfuzz.fuzztools import filetools
from certfuzz.fuzztools.filetools import delete_files_or_dirs
from certfuzz.minimizer import MinimizerError, WindowsMinimizer as Minimizer
from certfuzz.runners.errors import RunnerRegistryError

from certfuzz.iteration.errors import IterationError
from certfuzz.iteration.iteration_base3 import IterationBase3
#from certfuzz.iteration.iteration_base import IterationBase2


logger = logging.getLogger(__name__)

IOERROR_COUNT = 0
MAX_IOERRORS = 5


class Iteration(IterationBase3):
    def __init__(self, sf, rng_seed, current_seed, config, fuzzer_cls,
                 runner, debugger, dbg_class, keep_heisenbugs, keep_duplicates,
                 cmd_template, uniq_func, workdirbase, outdir, debug):
        IterationBase3.__init__(self, workdirbase)
        self.sf = sf
        self.r = None
        self.rng_seed = rng_seed
        self.current_seed = current_seed
        self.config = config
        self.fuzzer_cls = fuzzer_cls
        self.runner = runner
        self.debugger_module = debugger
        self.debugger_class = dbg_class
        self.debug = debug
        self.keep_uniq_faddr = config['runoptions']['keep_unique_faddr']
        self.keep_duplicates = keep_duplicates
        self.keep_heisenbugs = keep_heisenbugs
        self.cmd_template = string.Template(cmd_template)
        self.uniq_func = uniq_func
        self.fuzzed = False
        self.outdir = outdir
        self.crash = None
        self.success = False
        self.iteration_tmpdir_pfx = 'iteration_'
        self.minimizable = False

        if self.runner is None:
            # null runner case
            self.retries = 0
        else:
            # runner is not null
            self.retries = 4

    def __exit__(self, etype, value, traceback):

        global IOERROR_COUNT

        # Reset error count every time we do not have an error
        if not etype:
            IOERROR_COUNT = 0

        # check for exceptions we want to handle
        handled = False
        if etype is FuzzerExhaustedError:
            # let Fuzzer Exhaustion filter up to the campaign level
            handled = False
        elif etype is FuzzerInputMatchesOutputError:
            # Non-fuzzing happens sometimes, just log and move on
            logger.debug('Skipping seed %d, fuzzed == input', self.current_seed)
            handled = True
        elif etype is FuzzerError:
            logger.warning('Failed to fuzz, Skipping seed %d.', self.current_seed)
            handled = True
        elif etype is DebuggerFileError:
            logger.warning('Failed to debug, Skipping seed %d', self.current_seed)
            handled = True
        elif etype is RunnerRegistryError:
            logger.warning('Runner cannot set registry entries. Consider null runner in config?')
            # this is fatal, pass it up
            handled = False
        elif etype is IOError:
            IOERROR_COUNT += 1
            if IOERROR_COUNT > MAX_IOERRORS:
                # something is probably wrong, we should crash
                logger.critical('Too many IOErrors (%d in a row): %s', IOERROR_COUNT + 1, value)
            else:
                # we can keep going for a bit
                logger.error('Intercepted IOError, will try to continue: %s', value)
                handled = True

        # log something different if we failed to handle an exception
        if etype and not handled:
            logger.warning('Iteration terminating abnormally due to %s: %s', etype.__name__, value)
        else:
            logger.info('Done with iteration %d', self.current_seed)

        # count this iteration
        if self.success:
            self.record_success()
        else:
            self.record_failure()

        if self.debug and etype and not handled:
            # don't clean up if we're in debug mode and have an unhandled exception
            logger.debug('Skipping cleanup since we are in debug mode.')
        else:
            # wrap up this iteration
            logger.debug('Cleanup iteration %s', self.current_seed)
            # this iteration's temp dir
            paths = [self.working_dir]
            # sweep up any iteration temp dirs left behind previously
            pattern = os.path.join(self.workdirbase, self.iteration_tmpdir_pfx + '*')
            paths.extend(glob.glob(pattern))
            delete_files_or_dirs(paths)
            # wipe them out, all of them
            TmpReaper().clean_tmp()

        return handled

    def _fuzz(self):
        # generated test case (fuzzed input)
        logger.info('...fuzzing')
        fuzz_opts = self.config['fuzzer']
        fuzz_args = self.sf, self.working_dir, self.rng_seed, self.current_seed, fuzz_opts
        with self.fuzzer_cls(*fuzz_args) as fuzzer:
            fuzzer.fuzz()
            self.fuzzed = True
            self.r = fuzzer.range
            if self.r:
                logger.info('Selected r: %s', self.r)
        # decide if we can minimize this case later
        # do this here (and not sooner) because the fuzzer_cls could
        # decide at runtime whether it is or is not minimizable
        self.minimizable = fuzzer.is_minimizable and self.config['runoptions']['minimize']

        # hang on to this fuzzer instance, we use it in _run
        self.fuzzer = fuzzer

    def _run(self):
        # analysis is required in two cases:
        # 1) runner is not defined (self.runner == None)
        # 2) runner is defined, and detects crash (runner.saw_crash == True)
        # this takes care of case 1 by default
        analysis_needed = True
        if self.runner:
            logger.info('...running %s', self.runner.__name__)
            with self.runner(self.config['runner'],
                             self.cmd_template,
                             self.fuzzer.output_file_path,
                             self.working_dir) as runner:
                runner.run()
                # this takes care of case 2
                analysis_needed = runner.saw_crash
        # is further analysis needed?
        if analysis_needed:
            logger.info('...analyzing')
            cmdlist = get_command_args_list(self.cmd_template, self.fuzzer.output_file_path)[1]
            dbg_opts = self.config['debugger']
            fuzzed_file = BasicFile(self.fuzzer.output_file_path)
            self._build_crash(self.fuzzer, cmdlist, dbg_opts, fuzzed_file)
        else:
            logger.debug('...no crash')
        pass

    def _verify(self, testcase):
        keep_it, reason = self.keep_testcase(testcase)

        if not keep_it:
            logger.info('Candidate testcase rejected: %s', reason)
            testcase.should_proceed_with_analysis = False
            return

        logger.debug('Keeping testcase (reason=%s)', reason)
        testcase.should_proceed_with_analysis = True
        logger.info("Crash confirmed: %s Exploitability: %s Faulting Address: %s", testcase.crash_hash, testcase.exp, testcase.faddr)
        if self.minimizable:
            testcase.should_proceed_with_analysis = True
        self.success = True

    def _minimize(self, testcase):
        logger.info('Minimizing testcase %s', testcase.signature)
        logger.debug('config = %s', self.config)

        config = self._create_minimizer_cfg()

        debuggers.verify_supported_platform()

        kwargs = {'cfg': config,
                  'crash': testcase,
                  'seedfile_as_target': True,
                  'bitwise': False,
                  'confidence': 0.999,
                  'tempdir': self.working_dir,
                  'maxtime': self.config['runoptions']['minimizer_timeout']
                  }

        with Minimizer(**kwargs) as minimizer:
            minimizer.go()
            if len(minimizer.other_crashes):
                # minimzer found other crashes, so we should add them
                # to our list for subsequent processing
                self.crashes.extend(minimizer.other_crashes.values())

    def _analyze(self, testcase):
        pass

    def _report(self, testcase):
        self.copy_files(testcase)

    def keep_testcase(self, testcase):
        '''Given a testcase, decide whether it is a keeper. Returns a tuple
        containing a boolean indicating whether to keep the testcase, and
        a string containing the reason for the boolean result.
        @param testcase: a testcase object
        @return (bool,str)
        '''
        if testcase.is_crash:
            if self.keep_duplicates:
                return (True, 'keep duplicates')
            elif self.uniq_func(testcase.signature):
                # Check if crasher directory exists already
                target_dir = testcase._get_output_dir(self.outdir)
                if os.path.exists(target_dir):
                    return (False, 'skip duplicate %s' % testcase.signature)
                else:
                    return (True, 'unique')
            else:
                return (False, 'skip duplicate %s' % testcase.signature)
        elif not self.runner:
            return (False, 'not a crash')
        elif self.keep_heisenbugs:
            return (True, 'heisenbug')
        else:
            return (False, 'skip heisenbugs')

    def _create_minimizer_cfg(self):
        class DummyCfg(object):
            pass
        config = DummyCfg()
        config.backtracelevels = 5  # doesn't matter what this is, we don't use it
        config.debugger_timeout = self.config['debugger']['runtimeout']
        config.get_command_args_list = lambda x: get_command_args_list(self.cmd_template, x)[1]
        config.program = self.config['target']['program']
        config.killprocname = None
        config.exclude_unmapped_frames = False
        config.watchdogfile = os.devnull
        return config

    def _copy_seedfile(self):
        target = os.path.join(self.working_dir, self.sf.basename)
        logger.debug('Copy files to %s: %s', self.working_dir, target)
        shutil.copy(self.sf.path, target)

    def copy_files(self, crash):
        if not self.outdir:
            raise IterationError('Need a target dir to copy to')

        logger.debug('target_base=%s', self.outdir)

        target_dir = crash._get_output_dir(self.outdir)

        if os.path.exists(target_dir):
            logger.debug('Repeat crash, will not copy to %s', target_dir)
        else:
            # make sure target_base exists already
            filetools.find_or_create_dir(self.outdir)
            logger.debug('Copying to %s', target_dir)
            shutil.copytree(crash.tempdir, target_dir)
            assert os.path.isdir(target_dir)

    def record_success(self):
        crash = self.crashes[0]
        if self.r:
            # ranges should only get scored on the first crash
            # found in this iteration. Others found via minimization
            # don't count for this r
            # FIXME
            pass
            # self.r.record_success(crash.signature)
        # FIXME
        # self.sf.record_success(crash.signature)

    def record_failure(self):
        if self.r:
            # FIXME
            pass
            # self.r.record_failure()
        # FIXME
        # self.sf.record_failure()

    def _log_testcase(self, crash):
        # pretty-print the crash for debugging
        logger.debug('Crash:')
        from pprint import pformat
        formatted = pformat(crash.__dict__)
        for line in formatted.splitlines():
            logger.debug('... %s', line.rstrip())

    def _build_crash(self, fuzzer, cmdlist, dbg_opts, fuzzed_file):
        logger.debug('Building testcase object')
        with WindowsCrash(self.cmd_template, self.sf, fuzzed_file, cmdlist, fuzzer, self.debugger_class,
                   dbg_opts, self.working_dir, self.config['runoptions']['keep_unique_faddr'],
                   self.config['target']['program'], heisenbug_retries=self.retries,
                   copy_fuzzedfile=fuzzer.fuzzed_changes_input) as testcase:
            self._log_testcase(testcase)
            # put it on the queue for the analysis pipeline
            self.tc_candidate_q.put(testcase)
