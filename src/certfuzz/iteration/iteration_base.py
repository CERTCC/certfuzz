'''
Created on Feb 13, 2014

@author: adh
'''
import logging
import tempfile
import abc
from certfuzz.fuzztools.filetools import rm_rf
from certfuzz.fuzzers.errors import FuzzerExhaustedError, \
    FuzzerInputMatchesOutputError, FuzzerError
from certfuzz.minimizer.errors import MinimizerError
from certfuzz.debuggers.output_parsers.errors import DebuggerFileError
from certfuzz.runners.errors import RunnerRegistryError

logger = logging.getLogger(__name__)

IOERROR_COUNT = 0
MAX_IOERRORS = 5


class IterationBase(object):
    __metaclass__ = abc.ABCMeta
    _tmpdir_pfx = 'iteration_'
    _iteration_counter = 0

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
                 ):

        logger.debug('init')
        self.seedfile = seedfile
        self.seednum = seednum
        self.workdirbase = workdirbase
        self.outdir = outdir
        self.sf_set = sf_set
        self.cfg = config
        self.fuzzer_cls = fuzzer_cls
        self.runner_cls = runner_cls

        self.r = None

        minimizable = self.fuzzer_cls.is_minimizable and self.cfg[
            'runoptions'].get('minimize', False)
        if str(config['fuzzer']['fuzzer']).lower() == 'verify' and str(self.cfg['runoptions']['minimize']).lower() == 'string':
            # We will perform string minimization in verify mode
            minimizable = True
        self.pipeline_options = {'minimizable': minimizable, }

        if uniq_func is None:
            self.uniq_func = lambda _tc_id: True
        else:
            self.uniq_func = uniq_func

        self.working_dir = None

        self.testcases = []

        # flag that will decide whether we score as a success or failure
        self.success = False

        self.debug = True

        # extract some parts of the config for fuzzer and runner
        self._fuzz_opts = self.cfg['fuzzer']
        self._runner_options = self.cfg['runner']

    @abc.abstractproperty
    def tcpipeline_cls(self):
        '''
        Defines the class to use as a TestCasePipeline
        '''

    def __enter__(self):
        self.working_dir = tempfile.mkdtemp(prefix=self._tmpdir_pfx,
                                            dir=self.workdirbase)
        logger.debug('workdir=%s', self.working_dir)
#        self._setup_analysis_pipeline()

        return self.go

    def __exit__(self, etype, value, traceback):
        handled = False

        # increment the iteration counter
        IterationBase._iteration_counter += 1

        # increment the seedfile try counter
        self.seedfile.tries += 1

        if self.success:
            # score it so we can learn
            self.record_success()
        else:
            self.record_failure()

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
            logger.warning(
                'Runner cannot set registry entries. Consider null runner in config?')
            # this is fatal, pass it up
            handled = False
        elif etype is IOError:
            IOERROR_COUNT += 1
            if IOERROR_COUNT > MAX_IOERRORS:
                # something is probably wrong, we should crash
                logger.critical(
                    'Too many IOErrors (%d in a row): %s', IOERROR_COUNT + 1, value)
            else:
                # we can keep going for a bit
                logger.error(
                    'Intercepted IOError, will try to continue: %s', value)
                handled = True

        if self.debug and etype:
            # leave it behind if we're in debug mode
            # and there's a problem
            logger.debug('Skipping cleanup since we are in debug mode.')
            return handled

        # clean up
        rm_rf(self.working_dir)

        return handled

    def _pre_fuzz(self):
        self.fuzzer = self.fuzzer_cls(
            self.seedfile, self.working_dir, self.seednum, self._fuzz_opts)

    def _fuzz(self):
        with self.fuzzer:
            self.fuzzer.fuzz()

        self.r = self.fuzzer.range
        if self.r is not None:
            logger.debug('Selected r: %s', self.r)

    def _post_fuzz(self):
        pass

    def _pre_run(self):
        fuzzed_file = self.fuzzer.output_file_path
        workingdir_base = self.working_dir
        self.cmd_template = self.cfg['target']['cmdline_template']
        self.runner = self.runner_cls(
            self._runner_options, self.cmd_template, fuzzed_file, workingdir_base)

    def _run(self):
        with self.runner:
            self.runner.run()

    def _post_run(self):
        pass

    def construct_testcase(self):
        '''
        If the runner saw a crash, construct a test case
        and append it to the list of testcases to be analyzed further.
        '''
        if not self.runner.saw_crash:
            return

        logger.debug('Building testcase object')
        self._construct_testcase()

    def _construct_testcase(self):
        # should be implemented by child classes
        raise NotImplementedError

    def fuzz(self):
        '''
        Prepares a test case
        '''
        logger.debug('fuzz')
        self._pre_fuzz()
        self._fuzz()
        self._post_fuzz()

    def run(self):
        '''
        Runs a test case. Populates self.tc_candidate_q if it finds anything
        interesting.
        '''
        logger.debug('run')
        self._pre_run()
        self._run()
        self._post_run()

    def record_success(self):
        self.sf_set.record_success(key=self.seedfile.md5)
        if hasattr(self.r, 'id'):
            self.seedfile.rangefinder.record_success(key=self.r.id)

    def record_failure(self):
        self.record_tries()

    def record_tries(self):
        if self.seedfile.md5 in self.sf_set.arms:
            # Only record tries for seedfiles that haven't been removed
            self.sf_set.record_tries(key=self.seedfile.md5, tries=1)
            if hasattr(self.r, 'id'):
                self.seedfile.rangefinder.record_tries(key=self.r.id, tries=1)

    def process_testcases(self):
        if not len(self.testcases):
            # short circuit if nothing to do
            return

        # hand it off to our pipeline class
        with self.tcpipeline_cls(testcases=self.testcases,
                                 uniq_func=self.uniq_func,
                                 cfg=self.cfg,
                                 options=self.pipeline_options,
                                 outdir=self.outdir,
                                 workdirbase=self.working_dir,
                                 sf_set=self.sf_set) as pipeline:
            pipeline.go()

        self.success = pipeline.success

    def go(self):
        logger.debug('go')
        self.fuzz()
        self.run()
        self.construct_testcase()
        self.process_testcases()
