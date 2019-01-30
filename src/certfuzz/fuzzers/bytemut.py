import logging
import random

from certfuzz.fuzzers.fuzzer_base import MinimizableFuzzer
from certfuzz.fuzzers.fuzzer_base import is_fuzzable as _fuzzable


logger = logging.getLogger(__name__)


def fuzz(fuzz_input=None, seed_val=None, jump_idx=None, ratio_min=0.0,
         ratio_max=1.0, range_list=None, fuzzable_chars=None):
    '''
    Twiddle bytes of input and return output
    '''
    logging.debug('fuzz params: %d %d %f %f %s', seed_val, jump_idx, ratio_min, ratio_max, range_list)

    if seed_val is not None:
        random.seed(seed_val)
    if jump_idx is not None:
        random.jumpahead(jump_idx)

    ratio = random.uniform(ratio_min, ratio_max)
    inputlen = len(fuzz_input)

    chunksize = 2 ** 19  # 512k
    logger.debug('ratio=%f len=%d', ratio, inputlen)

    if range_list:
        chunksize = inputlen

    for chunk_start in xrange(0, inputlen, chunksize):
        chunk_end = min(chunk_start + chunksize, inputlen)
        chunk_len = chunk_end - chunk_start

        if range_list:
            chooselist = [x for x in xrange(inputlen) if _fuzzable(x, range_list)]
        else:
            chooselist = xrange(chunk_len)
        if fuzzable_chars is not None:
            chooselist = [x for x in chooselist if fuzz_input[x + chunk_start] in fuzzable_chars]

        nbytes_to_fuzz = int(round(ratio * len(chooselist)))
        bytes_to_fuzz = random.sample(chooselist, nbytes_to_fuzz)

        for idx in bytes_to_fuzz:
            offset = chunk_start + idx
            fuzz_input[offset] = random.getrandbits(8)

    return fuzz_input


class ByteMutFuzzer(MinimizableFuzzer):
    '''
    This fuzzer module randomly selects bytes in an input file and assigns
    them random values. The percent of the selected bytes can be tweaked by
    min_ratio and max_ratio. range_list specifies a range in the file to fuzz.
    Roughly similar to cmiller's 5 lines o' python, except clearly less space
    efficient.
    '''
    fuzzable_chars = None

    def _fuzz(self):
        self.range = self.sf.rangefinder.next_item()
        range_list = self.options.get('range_list')
        bytemutmaxratio = self.options.get('bytemutmaxratio')

        if bytemutmaxratio:
            self.range.max = bytemutmaxratio
            if self.range.min > bytemutmaxratio:
                self.range.min = bytemutmaxratio

        self.output = fuzz(fuzz_input=self.input,
                           seed_val=self.rng_seed,
                           jump_idx=self.iteration,
                           ratio_min=self.range.min,
                           ratio_max=self.range.max,
                           range_list=range_list,
                           fuzzable_chars=self.fuzzable_chars,
                           )

_fuzzer_class = ByteMutFuzzer
