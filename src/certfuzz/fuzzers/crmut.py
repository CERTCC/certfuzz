import logging

logger = logging.getLogger(__name__)

from .bytemut import ByteMutFuzzer

class CRMutFuzzer(ByteMutFuzzer):
    '''
    This fuzzer module randomly replaces single CR characters 0x0D with
    random values. The percent of the selected bytes can be tweaked by
    min_ratio and max_ratio. range_list specifies a range in the file to fuzz.
    '''
    fuzzable_chars = [0x0d]

_fuzzer_class = CRMutFuzzer
