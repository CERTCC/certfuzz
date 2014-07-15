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


logger = logging.getLogger(__name__)


class IterationBase3(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, workdirbase):
        logger.debug('init')
        self.workdirbase = workdirbase
        self.working_dir = None
        self.analyzer_classes = []

        self.candidates = Queue.Queue()
        self.verified = Queue.Queue()
        self.analyzed = Queue.Queue()

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

        self.analyzed.put(testcase)

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
        Runs a test case. Populates self.candidates if it finds anything
        interesting.
        '''
        logger.debug('run')
        self._pre_run()
        self._run()
        self._post_run()

    def verify(self, testcase):
        '''
        Verifies a test case.
        :param testcase:
        '''
        logger.debug('verify')
        self._pre_verify(testcase)
        self._verify(testcase)
        self._post_verify(testcase)

    def analyze(self, testcase):
        '''
        Analyzes a test case
        :param testcase:
        '''
        logger.debug('analyze')
        self._pre_analyze(testcase)
        self._analyze(testcase)
        self._post_analyze(testcase)

    def report(self, testcase):
        '''
        Prepares the test case report
        :param testcase:
        '''
        logger.debug('report')
        self._pre_report(testcase)
        self._report(testcase)
        self._post_report(testcase)

    def go(self):
        logger.debug('go')
        self.fuzz()
        self.run()

        # every test case is a candidate until verified
        # use a while loop so we have the option of adding
        # candidates during the loop
        while not self.candidates.empty():
            testcase = self.candidates.get()
            self.verify(testcase)

        while not self.verified.empty():
            testcase = self.verified.get()
            self.analyze(testcase)

        while not self.analyzed.empty():
            testcase = self.analyzed.get()
            self.report(testcase)


