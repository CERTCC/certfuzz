'''
Created on Feb 13, 2014

@author: adh
'''
import tempfile
import logging
import shutil
from certfuzz.file_handlers.watchdog_file import touch_watchdog_file
from certfuzz.analyzers.errors import AnalyzerEmptyOutputError

logger = logging.getLogger(__name__)


class IterationBase3(object):
    def __init__(self, workdirbase):
        logger.debug('init')
        self.workdirbase = workdirbase
        self.working_dir = None
        self.analyzer_classes = []

        self.candidates = []
        self.verified = []
        self.analyzed = []

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

    def _pre_fuzz(self):
        pass

    def _fuzz(self):
        pass

    def _post_fuzz(self):
        pass

    def _pre_run(self):
        pass

    def _run(self):
        pass

    def _post_run(self):
        pass

    def _pre_analyze(self, testcase):
        pass

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

        self.analyzed.append(testcase)

    def _post_analyze(self, testcase):
        pass

    def _pre_verify(self, testcase):
        pass

    def _verify(self, testcase):
        pass

    def _post_verify(self, testcase):
        pass

    def _pre_report(self, testcase):
        pass

    def _report(self, testcase):
        pass

    def _post_report(self, testcase):
        pass

    def fuzz(self):
        logger.debug('fuzz')
        self._pre_fuzz()
        self._fuzz()
        self._post_fuzz()

    def run(self):
        logger.debug('run')
        self._pre_run()
        self._run()
        self._post_run()

    def verify(self, testcase):
        logger.debug('verify')
        self._pre_verify(testcase)
        self._verify(testcase)
        self._post_verify(testcase)

    def analyze(self, testcase):
        logger.debug('analyze')
        self._pre_analyze(testcase)
        self._analyze(testcase)
        self._post_analyze(testcase)

    def report(self, testcase):
        logger.debug('report')
        self._pre_report(testcase)
        self._report(testcase)
        self._post_report(testcase)

    def go(self):
        logger.debug('go')
        self.fuzz()
        self.run()

        # short circuit if nothing found
        if not self.candidates:
            return

        # every test case is a candidate until verified
        # use a while loop so we have the option of adding
        # candidates during the loop
        while len(self.candidates) > 0:
            testcase = self.candidates.pop(0)
            self.verify(testcase)

        # analyze each verified crash
        while len(self.verified) > 0:
            testcase = self.verified.pop(0)
            self.analyze(testcase)

        # construct output bundle for each analyzed test case
        while len(self.analyzed) > 0:
            testcase = self.analyzed.pop(0)
            self.report(testcase)


