'''
Created on Feb 13, 2014

@author: adh
'''
import logging
import tempfile
import abc
from certfuzz.fuzztools.filetools import rm_rf

logger = logging.getLogger(__name__)


class IterationBase3(object):
    __metaclass__ = abc.ABCMeta
    _tmpdir_pfx = 'iteration_'

    def __init__(self,
                 seedfile=None,
                 seednum=None,
                 workdirbase=None,
                 outdir=None,
                 sf_set=None,
                 rf=None,
                 uniq_func=None,
                 config=None,
                 r=None):

        logger.debug('init')
        self.seedfile = seedfile
        self.seednum = seednum
        self.workdirbase = workdirbase
        self.outdir = outdir
        self.sf_set = sf_set
        self.rf = rf
        self.cfg = config
        self.r = r

        self.pipeline_options = {}

        if uniq_func is None:
            self.uniq_func = lambda _tc_id: True
        else:
            self.uniq_func = uniq_func

        self.working_dir = None

        self.testcases = []

        # flag that will decide whether we score as a success or failure
        self.success = False

        self.debug = True

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

        if self.success:
            # score it so we can learn
            self.record_success()
        else:
            self.record_failure()

        if self.debug and etype:
            # leave it behind if we're in debug mode
            # and there's a problem
            logger.debug('Skipping cleanup since we are in debug mode.')
            return handled

        # clean up
        rm_rf(self.working_dir)
        return handled

    def _pre_fuzz(self):
        pass

    def _fuzz(self):
        with self.fuzzer:
            self.fuzzer.fuzz()

    def _post_fuzz(self):
        pass

    def _pre_run(self):
        pass

    @abc.abstractmethod
    def _run(self):
        pass

    def _post_run(self):
        pass

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
        self.rf.record_success(key=self.r.id)

    def record_failure(self):
        self.record_tries()

    def record_tries(self):
        self.sf_set.record_tries(key=self.seedfile.md5, tries=1)
        self.rf.record_tries(key=self.r.id, tries=1)

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
                                 workdirbase=self.working_dir) as pipeline:
            pipeline()

    def go(self):
        logger.debug('go')
        self.fuzz()
        self.run()
        self.process_testcases()
