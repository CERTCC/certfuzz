"""This fuzzer module iterates through an input file, trying every byte value
as it goes. E.g. try 0-255 for the first byte, 0-255 for the second byte, etc.
"""
from . import MinimizableFuzzer
from . import FuzzerError
from . import FuzzerExhaustedError
import logging

logger = logging.getLogger(__name__)


def fuzz(*args):
    return WaveFuzzer(*args).fuzz()


class WaveFuzzerError(FuzzerError):
    pass


class WaveFuzzer(MinimizableFuzzer):
    def _fuzz(self):
        """Twiddle bytes of input_file_path and write output to output_file_path"""

        if self.options.get('use_range_list'):
            bytes_to_fuzz = []
            for (start, end) in self.options['range_list']:
                bytes_to_fuzz.extend(xrange(start, end + 1))
        else:
            bytes_to_fuzz = xrange(len(self.input))

        # we can calculate the byte and value based on the number of tries
        # on this seed file
        (q, r) = divmod(self.sf.tries, 256)
        if q < len(bytes_to_fuzz):
            self.input[bytes_to_fuzz[q]] = r
        else:
            #indicate we didn't fuzz the file for this iteration
            raise FuzzerExhaustedError('Iteration exceeds available values')

        logger.debug('%s - set byte 0x%02x to 0x%02x', self.sf.basename, q, r)

        self.fuzzed = self.input

_fuzzer_class = WaveFuzzer
