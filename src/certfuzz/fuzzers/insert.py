"""
"""
import logging
from random import getrandbits

from certfuzz.fuzzers.fuzzer_base import Fuzzer
from certfuzz.fuzzers.errors import FuzzerExhaustedError


logger = logging.getLogger(__name__)


class InsertFuzzer(Fuzzer):
    '''
    This fuzzer module iterates through an input file, inserting a random byte
    between every byte position as it goes. E.g. insert before byte 0, before
    byte 1, etc.
    '''
    def _fuzz(self):
        '''
        Insert individual bytes of input and put output in self.output
        '''

        # TODO: add range list support to insert fuzzer
#        if self.options.get('use_range_list'):
#            bytes_to_fuzz = []
#            for (start, end) in self.options['range_list']:
#                    bytes_to_fuzz.extend(xrange(start, end + 1))
#        else:
#            bytes_to_fuzz = xrange(len(byte_buffer))
        bytes_to_fuzz = xrange(len(self.input))

        # we can calculate the byte to insert on based on the number of tries
        # on this seed file
        byte_pos = self.sf.tries
        byte_to_insert = getrandbits(8)

        if byte_pos < len(bytes_to_fuzz):
            self.input.insert(byte_pos, byte_to_insert)
        else:
            # indicate we didn't fuzz the file for this iteration
            raise FuzzerExhaustedError('Iteration exceeds available values')

        logger.debug('%s - inserted byte 0x%02x at 0x%02x', self.sf.basename,
                     byte_to_insert, byte_pos)

        self.output = self.input

_fuzzer_class = InsertFuzzer
