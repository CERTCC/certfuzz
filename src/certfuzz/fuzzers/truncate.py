'''
Created on Jul 12, 2012

@organization: cert.org
'''
import logging

from certfuzz.fuzzers import Fuzzer
from certfuzz.fuzzers.errors import FuzzerExhaustedError


logger = logging.getLogger(__name__)


class TruncateFuzzer(Fuzzer):
    '''
    This fuzzer module iterates through an input file, dropping an additional
    byte from the file each time. (The file gets shorter.)

    @raise FuzzerExhaustedError: when the output file reaches zero length
    '''
    def _fuzz(self):
        '''
        Drop individual bytes of input and put output in self.output
        '''

        # self.tries starts at zero
        # so when tries = 0, byte_pos = -1
        # 1 : -2 etc
        byte_pos = -(self.sf.tries + 1)
        truncated = self.input[:byte_pos]

        if not len(truncated):
            raise FuzzerExhaustedError('Iteration exceeds available values')

        logger.debug('%s - truncated %s bytes', self.sf.basename, byte_pos)

        self.output = truncated

_fuzzer_class = TruncateFuzzer
