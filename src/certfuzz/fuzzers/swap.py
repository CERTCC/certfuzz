"""This fuzzer module iterates through an input file, swapping neighboring
bytes.
"""
import logging
from . import MinimizableFuzzer, FuzzerError, FuzzerExhaustedError

logger = logging.getLogger(__name__)


class SwapFuzzerError(FuzzerError):
    pass


class SwapFuzzer(MinimizableFuzzer):
    '''
    Step through the input file swapping each byte with its neighbor
    '''

    def _fuzz(self):
        """swap bytes of input_file_path and write output to output_file_path"""

        # we can calculate which bytes to swap based on the number of tries
        # we've made on this seedfile
        a = self.sf.tries
        b = a + 1

        if b >= len(self.input):
            raise FuzzerExhaustedError('Iteration exceeds seed file length')

        logger.debug('%s - swap bytes %d <-> %d', self.sf.basename, a, b)
        self.input[b], self.input[a] = self.input[a], self.input[b]
        self.fuzzed = self.input

_fuzzer_class = SwapFuzzer
