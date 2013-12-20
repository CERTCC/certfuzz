import logging

logger = logging.getLogger(__name__)

from .bytemut import ByteMutFuzzer


class CRLFMutFuzzer(ByteMutFuzzer):
    '''
    This fuzzer module randomly replaces single CR and LF characters 0x0D 0x0A with
    random values. The percent of the selected bytes can be tweaked by
    min_ratio and max_ratio. range_list specifies a range in the file to fuzz.
    '''
    fuzzable_chars = [0x0D, 0x0A]

_fuzzer_class = CRLFMutFuzzer
