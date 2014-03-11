import logging

from certfuzz.fuzzers.bytemut import ByteMutFuzzer


logger = logging.getLogger(__name__)


class NullMutFuzzer(ByteMutFuzzer):
    '''
    This fuzzer module randomly replaces single null characters 0x00 with
    random values. The percent of the selected bytes can be tweaked by
    min_ratio and max_ratio. range_list specifies a range in the file to fuzz.
    '''
    fuzzable_chars = [0x00]

_fuzzer_class = NullMutFuzzer
