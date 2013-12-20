import logging

logger = logging.getLogger(__name__)

from .bytemut import ByteMutFuzzer


class NullMutFuzzer(ByteMutFuzzer):
    '''
    This fuzzer module randomly replaces single null characters 0x00 with
    random values. The percent of the selected bytes can be tweaked by
    min_ratio and max_ratio. range_list specifies a range in the file to fuzz.
    '''
    fuzzable_chars = [0x00]

_fuzzer_class = NullMutFuzzer
