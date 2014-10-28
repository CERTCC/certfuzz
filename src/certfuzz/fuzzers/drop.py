"""
"""
import logging

from certfuzz.fuzzers import Fuzzer
from certfuzz.fuzzers.errors import FuzzerExhaustedError


logger = logging.getLogger(__name__)


class DropFuzzer(Fuzzer):
    '''
    This fuzzer module iterates through an input file, dropping each byte position
    as it goes. E.g. drop byte 0, drop byte 1, etc.
    '''
    def _fuzz(self):
        '''
        Drop individual bytes of input and put output in self.output
        '''

        # TODO: add range list support to drop fuzzer
#        if self.options.get('use_range_list'):
#            bytes_to_fuzz = []
#            for (start, end) in self.options['range_list']:
#                    bytes_to_fuzz.extend(xrange(start, end + 1))
#        else:
#            bytes_to_fuzz = xrange(len(byte_buffer))
        bytes_to_fuzz = xrange(len(self.input))

        # we can calculate the byte and value based on the number of tries
        # on this seed file
        byte_pos = self.sf.tries
        if byte_pos < len(bytes_to_fuzz):
            del self.input[byte_pos]
        else:
            #indicate we didn't fuzz the file for this iteration
            raise FuzzerExhaustedError('Iteration exceeds available values')

        logger.debug('%s - dropped byte 0x%02x', self.sf.basename, byte_pos)

        self.output = self.input

_fuzzer_class = DropFuzzer
