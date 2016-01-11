'''
Created on Mar 2, 2012

@author: adh
'''
import glob
import logging
import os
import string

from certfuzz.config.config_windows import get_command_args_list
from certfuzz.crash.crash_windows import WindowsCrash
from certfuzz.debuggers.output_parsers.errors import DebuggerFileError
from certfuzz.file_handlers.basicfile import BasicFile
from certfuzz.file_handlers.tmp_reaper import TmpReaper
from certfuzz.fuzzers.errors import FuzzerError
from certfuzz.fuzzers.errors import FuzzerExhaustedError
from certfuzz.fuzzers.errors import FuzzerInputMatchesOutputError
from certfuzz.minimizer.errors import MinimizerError
from certfuzz.fuzztools.filetools import delete_files_or_dirs
from certfuzz.iteration.iteration_base3 import IterationBase3
from certfuzz.runners.errors import RunnerRegistryError
from certfuzz.testcase_pipeline.tc_pipeline_windows import WindowsTestCasePipeline


# from certfuzz.iteration.iteration_base import IterationBase2
logger = logging.getLogger(__name__)

IOERROR_COUNT = 0
MAX_IOERRORS = 5


class WindowsIteration(IterationBase3):
    tcpipeline_cls = WindowsTestCasePipeline

    def __init__(self,
                 seedfile=None,
                 seednum=None,
                 workdirbase=None,
                 outdir=None,
                 sf_set=None,
                 uniq_func=None,
                 config=None,
                 fuzzer_cls=None,
                 runner_cls=None,
                 keep_heisenbugs=None,
                 keep_duplicates=None,
                 cmd_template=None,
                 debug=False,
                 ):
        IterationBase3.__init__(self,
                                seedfile,
                                seednum,
                                workdirbase,
                                outdir,
                                sf_set,
                                uniq_func,
                                config,
                                fuzzer_cls,
                                runner_cls,
                                )

        self.debug = debug
        # TODO: do we use keep_uniq_faddr at all?
        self.keep_uniq_faddr = config['runoptions']['keep_unique_faddr']

        self.cmd_template = string.Template(cmd_template)

        if self.runner_cls is None:
            # null runner_cls case
            self.retries = 0
        else:
            # runner_cls is not null
            self.retries = 4

        self.pipeline_options = {'keep_duplicates': keep_duplicates,
                                 'keep_heisenbugs': keep_heisenbugs,
                                 'minimizable': False,
                                 'cmd_template': self.cmd_template,
                                 'used_runner': self.runner_cls is not None,
                                 'minimizable': self.fuzzer_cls.is_minimizable and self.cfg['runoptions']['minimize']
                                 }

    def __exit__(self, etype, value, traceback):
        handled = IterationBase3.__exit__(self, etype, value, traceback)

        global IOERROR_COUNT

        # Reset error count every time we do not have an error
        if not etype:
            IOERROR_COUNT = 0

        # check for exceptions we want to handle
        if etype is FuzzerExhaustedError:
            # let Fuzzer Exhaustion filter up to the campaign level
            handled = False
        elif etype is FuzzerInputMatchesOutputError:
            # Non-fuzzing happens sometimes, just log and move on
            logger.debug('Skipping seed %d, fuzzed == input', self.seednum)
            handled = True
        elif etype is FuzzerError:
            logger.warning('Failed to fuzz, Skipping seed %d.', self.seednum)
            handled = True
        elif etype is MinimizerError:
            logger.warning('Failed to minimize %d, Continuing.', self.seednum)
            handled = True
        elif etype is DebuggerFileError:
            logger.warning('Failed to debug, Skipping seed %d', self.seednum)
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
            logger.warning('WindowsIteration terminating abnormally due to %s: %s', etype.__name__, value)
        else:
            logger.info('Done with iteration %d', self.seednum)

        if self.debug and etype and not handled:
            # don't clean up if we're in debug mode and have an unhandled exception
            logger.debug('Skipping cleanup since we are in debug mode.')
        else:
            self._tidy()

        return handled

    def _tidy(self):
        # wrap up this iteration
        paths = []
        # sweep up any iteration temp dirs left behind previously
        pattern = os.path.join(self.workdirbase, self._tmpdir_pfx + '*')
        paths.extend(glob.glob(pattern))
        delete_files_or_dirs(paths)
        # wipe them out, all of them
        TmpReaper().clean_tmp()

    def _pre_fuzz(self):
        fuzz_opts = self.cfg['fuzzer']
        self.fuzzer = self.fuzzer_cls(self.seedfile, self.working_dir, self.seednum, fuzz_opts)

    def _pre_run(self):
        options = self.cfg['runner']
        cmd_template = self.cmd_template
        fuzzed_file = self.fuzzer.output_file_path
        workingdir_base = self.working_dir

        self.runner = self.runner_cls(options, cmd_template, fuzzed_file, workingdir_base)

    def _run(self):
        # analysis is required in two cases:
        # 1) runner_cls is not defined (self.runner_cls == None)
        # 2) runner_cls is defined, and detects crash (runner_cls.saw_crash == True)
        # this takes care of case 1 by default
        # TODO: does case 1 ever happen?
        analysis_needed = True
        if self.runner_cls:
            with self.runner:
                self.runner.run()
                # this takes care of case 2
            analysis_needed = self.runner.saw_crash

        # is further analysis needed?
        if not analysis_needed:
            return

        self._construct_testcase()

    def _construct_testcase(self):
        logger.debug('Building testcase object')
        with WindowsCrash(cmd_template=self.cmd_template,
                          seedfile=self.seedfile,
                          fuzzedfile=BasicFile(self.fuzzer.output_file_path),
                          cmdlist=get_command_args_list(self.cmd_template, self.fuzzer.output_file_path)[1],
                          fuzzer=self.fuzzer,
                          dbg_opts=self.cfg['debugger'],
                          workingdir_base=self.working_dir,
                          keep_faddr=self.cfg['runoptions']['keep_unique_faddr'],
                          program=self.cfg['target']['program'],
                          heisenbug_retries=self.retries,
                          copy_fuzzedfile=self.fuzzer.fuzzed_changes_input) as testcase:

            # put it on the list for the analysis pipeline
            self.testcases.append(testcase)
