'''
Created on Dec 8, 2010

@organization: cert.org
'''
import logging
import math

from certfuzz.fuzztools.errors import RangeFinderError
from certfuzz.fuzztools.range import Range
from certfuzz.scoring.scorable_set import ScorableSet2


range_scale_factor = (math.sqrt(5) + 1.0) / 2.0

logger = logging.getLogger(__name__)


class RangeFinder(ScorableSet2):
    '''
    Provides facilities to maintain:
        1. a set of ranges (typically from min=1.0/filesize to max=1.0-1.0/filesize)
        2. scores for each range
        3. a probability distribution across all ranges
    as well as a picker method to randomly choose a range based on the probability distribution.
    '''
    def __init__(self, low, high, logfile, datafile=None):

        super(self.__class__, self).__init__(datafile=datafile)

        self.min = low
        self.max = high
        # the lowest range must have at least abs_min as its max
        # so that we don't wind up fuzzing a range of 0.000000:0.000000
        self.abs_min = 0.000001
        if self.max < self.min:
            raise RangeFinderError('max cannot be less than min')

        self.logfile = logfile
        logger.debug('Rangefinder log: %s', self.logfile)

        self._set_logger()

        self._set_ranges()

    def __getstate__(self):
        # we can't pickle the logger.
        # But that's okay. We can get it back in __setstate__
        state = ScorableSet2.__getstate__(self)
        del state['logger']
        return state

    def __setstate__(self, d):
        self.__dict__.update(d)
        for k, thing in self.things:
            assert type(thing) == Range, 'Type is %s' % type(thing)
        # recover the logger we had to drop in __getstate__
        self._set_logger()

    def _set_logger(self):
        self.logger = logging.getLogger(self.logfile)
        self.logger.setLevel(logging.INFO)

    def _exp_range(self, low, factor):
        high = low * factor
        # don't overshoot the high
        if high > self.max:
            high = self.max
        # don't undershoot abs_min
        if high < self.abs_min:
            high = self.abs_min
        return high

    def _set_ranges(self):
        rmin = self.min
        ranges = []
        while rmin < self.max:
            rmax = self._exp_range(rmin, range_scale_factor)
            ranges.append(Range(rmin, rmax))
            rmin = rmax

        # sometimes the last range might be smaller than the next to the last range
        # fix that if it happens
        (penultimate, ultimate) = ranges[-2:]
        if ultimate.span < penultimate.span:
            # create a new range to span both ranges
            merged_range = Range(penultimate.min, ultimate.max)
            # remove the last two ranges
            ranges = ranges[:-2]
            # and replace them with the merged range
            ranges.append(merged_range)

        for r in ranges:
            self.add_item(r.__repr__(), r)

        self.logger.debug('Ranges: [%s]', ', '.join([str(r) for r in self.things.keys()]))

