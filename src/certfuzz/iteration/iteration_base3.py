'''
Created on Feb 13, 2014

@author: adh
'''
import logging
import shutil
import tempfile

from certfuzz.analyzers.errors import AnalyzerEmptyOutputError

from certfuzz.file_handlers.watchdog_file import touch_watchdog_file
import abc
import Queue
from certfuzz.helpers.coroutine import coroutine


logger = logging.getLogger(__name__)


class IterationBase3(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, workdirbase):
        logger.debug('init')
        self.workdirbase = workdirbase
        self.working_dir = None
        self.analyzer_classes = []

        self.tc_candidate_q = Queue.Queue()

        self.analysis_pipeline = self.verify(self.analyze(self.report()))

        self.debug = True

    def __enter__(self):
        self.working_dir = tempfile.mkdtemp(prefix='iteration-', dir=self.workdirbase)
        logger.debug('workdir=%s', self.working_dir)
        return self

    def __exit__(self, etype, value, traceback):
        handled = False

        if etype and self.debug:
            # leave it behind if we're in debug mode
            # and there's a problem
            logger.debug('Skipping cleanup since we are in debug mode.')
        else:
            shutil.rmtree(self.working_dir)

        return handled

    @abc.abstractmethod
    def _pre_fuzz(self):
        pass

    @abc.abstractmethod
    def _fuzz(self):
        pass

    @abc.abstractmethod
    def _post_fuzz(self):
        pass

    @abc.abstractmethod
    def _pre_run(self):
        pass

    @abc.abstractmethod
    def _run(self):
        pass

    @abc.abstractmethod
    def _post_run(self):
        pass

    @abc.abstractmethod
    def _pre_analyze(self, testcase):
        pass

    @abc.abstractmethod
    def _analyze(self, testcase):
        '''
        Loops through all known analyzer_classes for a given testcase
        :param testcase:
        '''
        for analyzer_class in self.analyzer_classes:
            touch_watchdog_file()

            analyzer_instance = analyzer_class(self.cfg, testcase)
            if analyzer_instance:
                try:
                    analyzer_instance.go()
                except AnalyzerEmptyOutputError:
                    logger.warning('Unexpected empty output from analyzer_class. Continuing')

    @abc.abstractmethod
    def _post_analyze(self, testcase):
        pass

    @abc.abstractmethod
    def _pre_verify(self, testcase):
        pass

    @abc.abstractmethod
    def _verify(self, testcase):
        pass

    @abc.abstractmethod
    def _post_verify(self, testcase):
        pass

    @abc.abstractmethod
    def _pre_report(self, testcase):
        pass

    @abc.abstractmethod
    def _report(self, testcase):
        pass

    @abc.abstractmethod
    def _post_report(self, testcase):
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

    @coroutine
    def verify(self, target=None):
        '''
        Verifies that a test case is unique before sending the test case. Acts
        as a filter on the analysis pipeline.
        :param testcase:
        '''
        logger.debug('Verifier standing by for testcases')
        while True:
            testcase = (yield)

            logger.debug('verify testcase')
            self._pre_verify(testcase)
            self._verify(testcase)
            self._post_verify(testcase)

            if target is not None:
                if testcase.is_unique:
                    # we're ready to proceed with this testcase
                    # so send it downstream
                    target.send(testcase)

    @coroutine
    def analyze(self, target=None):
        '''
        Analyzes a test case before passing it down the pipeline
        :param testcase:
        '''
        logger.debug('Analyzer standing by for testcases')
        while True:
            testcase = (yield)

            logger.debug('analyze testcase')
            self._pre_analyze(testcase)
            self._analyze(testcase)
            self._post_analyze(testcase)

            if target is not None:
                target.send(testcase)

    @coroutine
    def report(self, target=None):
        '''
        Prepares the test case report.
        :param testcase:
        '''
        logger.debug('Reporter standing by for testcases')
        while True:
            testcase = (yield)

            logger.debug('report testcase')
            self._pre_report(testcase)
            self._report(testcase)
            self._post_report(testcase)

            if target is not None:
                target.send(testcase)

    def go(self):
        logger.debug('go')
        self.fuzz()
        self.run()

        # every test case is a candidate until verified
        # use a while loop so we have the option of adding
        # tc_candidate_q during the loop
        while not self.tc_candidate_q.empty():
            testcase = self.tc_candidate_q.get()
            self.analysis_pipeline.send(testcase)
