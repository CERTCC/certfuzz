'''
Created on Jan 13, 2016

@author: adh
'''
from certfuzz.reporters.reporter_base import ReporterBase
import logging


logger = logging.getLogger(__name__)


class TestcaseLoggerReporter(ReporterBase):
    '''
    Logs testcase data
    '''

    def go(self):
        tc = self.testcase
        logger.info('crash=%s seen in seedfile=%s outfile=%s at pc=%s',
                    tc.signature,
                    tc.seedfile.basename,
                    tc.fuzzedfile.path,
                    tc.pc
                    )
