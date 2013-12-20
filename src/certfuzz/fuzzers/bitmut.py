from . import MinimizableFuzzer
from random import jumpahead, sample, uniform, seed
import logging

logger = logging.getLogger(__name__)

class BitMutFuzzer(MinimizableFuzzer):
    '''
    This fuzzer module randomly selects bits in an input file and flips them.
    The percent of the selected bits can be tweaked by min_ratio and max_ratio.
    range_list specifies a range in the file to fuzz. Roughly similar to zzuf's
    mutation strategy.
    '''
    def _fuzz(self):
        """Twiddle bits of input_file_path and write output to output_file_path"""
        # rng_seed is the based on the input file
        seed(self.rng_seed)
        jumpahead(self.iteration)

        # select a ratio of bytes to fuzz
        self.range = self.sf.rangefinder.next_item()
        self.ratio = uniform(self.range.min, self.range.max)

        chooselist = []
        # only add bytes in range to the bytes we can fuzz
        range_list = self.options.get('range_list')
        if range_list:
            max_index = len(self.input) - 1
            for (start, end) in range_list:
                if start > end:
                    logger.warning('Skipping range_list item %s-%s (start exceeds end)', start, end)
                    continue
                elif start > max_index:
                    # we can't go past the end of the file
                    logger.debug('Skipping range_list item %s-%s (start exceeds max)', start, end)
                    continue

                # figure out where the actual end of this range is
                last = min(end, max_index)
                if last != end:
                    logger.debug('Reset range end from to %s to %s (file length exceeded)', end, last)

                # seems legit...proceed
                chooselist.extend(xrange(start, last + 1))
        else:
            # they're all available to fuzz
            chooselist.extend(xrange(len(self.input)))

        # build the list of bits we're allowed to flip
        # since chooselist is the list of bytes we can fuzz
        # protobitlist will be the base position of the first
        # bit we are allowed to fuzz in each of those bytes
        protobitlist = [x * 8 for x in chooselist]
        bitlist = []
        for b in protobitlist:
            for i in xrange(0, 8):
                # here we fill in the actual bits we are
                # allowed to fuzz
                # this will add b, b+1, b+2...b+7
                bitlist.append(b + i)

        # calculate num of bits to flip
        bit_flip_count = int(round(self.ratio * len(bitlist)))
        indices_to_flip = sample(bitlist, bit_flip_count)

        # create mask to xor with input
        mask = bytearray(len(self.input))
        for i in indices_to_flip:
            (byte_index, bit_index) = divmod(i, 8)
            mask[byte_index] = mask[byte_index] | (1 << bit_index)

        # apply the mask to the input
        for idx, val in enumerate(self.input):
            self.input[idx] = mask[idx] ^ val

        self.fuzzed = self.input

_fuzzer_class = BitMutFuzzer
