'''
Created on Oct 23, 2012

@organization: cert.org
'''
import logging

logger = logging.getLogger(__name__)

class Runner(object):
    '''
    classdocs
    '''
    def __init__(self, options, cmd_template, fuzzed_file, workingdir_base):
        '''
        Constructor
        '''
        logger.debug('Initialize Runner')
        if options is None:
            options = {}

        self.hideoutput = options.get('hideoutput', False)
        self.runtimeout = options.get('runtimeout', 5)
        self.saw_crash = False
        self.fuzzed_file = fuzzed_file

        self.workingdir = workingdir_base

    def __enter__(self):
        '''
        Override this method with your own setup code
        (don't forget to return self)
        '''
        return self

    def __exit__(self, etype, value, traceback):
        '''
        Override this with your own cleanup code
        @param etype:
        @param value:
        @param traceback:
        '''
        pass

    def kill(self, p):
        raise NotImplementedError

    def run(self):
        self._prerun()
        self._run()
        self._postrun()

    def _prerun(self):
        pass

    def _run(self):
        raise NotImplementedError

    def _postrun(self):
        pass
