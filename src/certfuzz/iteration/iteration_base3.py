'''
Created on Feb 13, 2014

@author: adh
'''
class IterationBase3(object):
    def __init__(self, workdirbase):
        self.workdirbase = workdirbase
        self.working_dir = None
        self.analyzers = None
        self.candidates = []
        self.verified = []
        self.analyzed = []

    def __enter__(self):
        self.working_dir = tempfile.mkdtemp(prefix='iteration-', dir=self.workdirbase)
        logger.debug('workdir=%s', self.working_dir)
        return self

    def __exit__(self, etype, value, traceback):
        shutil.rmtree(self.working_dir)

    def _prefuzz(self):
        pass

    def _fuzz(self):
        pass

    def _postfuzz(self):
        pass

    def _prerun(self):
        pass

    def _run(self):
        pass

    def _postrun(self):
        pass

    def _preanalyze(self, testcase):
        pass

    def _analyze(self, testcase):
        '''
        Loops through all known analyzers for a given testcase
        :param testcase:
        '''
        for analyzer in self.analyzers:
            analyzer(testcase)

    def _postanalyze(self, testcase):
        pass

    def _preverify(self, testcase):
        pass

    def _verify(self, testcase):
        pass

    def _postverify(self, testcase):
        pass

    def fuzz(self):
        self._prefuzz()
        self._fuzz()
        self._postfuzz()

    def run(self):
        self._prerun()
        self._run()
        self._postrun()

    def verify(self, testcase):
        self._preverify(testcase)
        self._verify(testcase)
        self._postverify(testcase)

    def analyze(self, testcase):
        self._preanalyze(testcase)
        self._analyze(testcase)
        self._postanalyze(testcase)

    def construct_report(self, testcase):
        pass

    def go(self):
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
            self.construct_report(testcase)


