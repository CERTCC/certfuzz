'''
Created on Jan 13, 2016

@author: adh
'''
from certfuzz.reporters.reporter_base import ReporterBase

class TestcaseLoggerReporter(ReporterBase):
    '''
    Invokes the testcase's logger to report out testcase data
    '''

    def go(self):
        tc = self.testcase
        # whether it was unique or not, record some details for posterity
        # record the details of this crash so we can regenerate it later if needed
        tc.logger.info('seen in seedfile=%s at seed=%d range=%s outfile=%s',
                       tc.seedfile.basename,
                       tc.seednum,
                       tc.range,
                       tc.fuzzedfile.path
                       )
        tc.logger.info('PC=%s', tc.pc)
