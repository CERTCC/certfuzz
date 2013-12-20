'''
Created on Mar 16, 2011

@organization: cert.org
'''
import os
import json

from .basicfile import BasicFile
from .errors import SeedFileError
from ..fuzztools.rangefinder import RangeFinder
from ..fuzztools import filetools
from ..scoring.scorable_thing import ScorableThing

# TODO: replace with a common function in some helper module
def print_dict(d, indent=0):
    for (k, v) in d.iteritems():
        indent_str = '  ' * indent
        if isinstance(v, dict):
            print indent_str + k
            print_dict(v, indent + 1)
        else:
            print indent_str + "%s (%s): %s" % (k, type(v).__name__, v)

# ScorableThing mixin gives us the probability stuff needed for use as part of
# a scorable set like SeedfileSet
class SeedFile(BasicFile, ScorableThing):
    '''
    '''

    def __init__(self, output_base_dir, path):
        '''
        Creates an output dir for this seedfile based on its md5 hash.
        @param output_base_dir: The base directory for output files
        @raise SeedFileError: zero-length files will raise a SeedFileError
        '''
        BasicFile.__init__(self, path)
        ScorableThing.__init__(self, key=self.md5)

        if not self.len > 0:
            raise SeedFileError('You cannot do bitwise fuzzing on a zero-length file: %s' % self.path)

        self.output_dir = os.path.join(output_base_dir, self.md5)
        # use len for bytewise, bitlen for bitwise
        if self.len > 1:
            self.range_min = 1.0 / self.len
            self.range_max = 1.0 - self.range_min
        else:
            self.range_min = 0
            self.range_max = 1

        # output_dir might not exist, so create it
        if not os.path.exists(self.output_dir):
            filetools.make_directories(self.output_dir)

        self.rangefinder = self._get_rangefinder()

    def _get_rangefinder(self):
        rf_log = os.path.join(self.output_dir, 'rangefinder.log')
        return RangeFinder(self.range_min, self.range_max, rf_log)

    def __getstate__(self):
        '''
        Pickle a SeedFile object
        @return a dict representation of the pickled object
        '''
        state = self.__dict__.copy()
        state['rangefinder'] = self.rangefinder.__getstate__()
        return state

    def __setstate__(self, state):
        old_rf = state.pop('rangefinder')

        self.a = state['a']
        self.b = state['b']
        self.seen = state['seen']
        self.successes = state['successes']
        self.tries = state['tries']
        self.uniques_only = state['uniques_only']

        # rebuild the rangefinder
        new_rf = self._get_rangefinder()
        old_ranges = old_rf['things']
        for k, old_range in old_ranges.iteritems():
            if k in new_rf.things:
                # things = ranges
                new_range = new_rf.things[k]
                for attr in ['a', 'b', 'probability', 'seen', 'successes', 'tries']:
                    setattr(new_range, attr, old_range[attr])
        self.rangefinder = new_rf

    def cache_key(self):
        return 'seedfile-%s' % self.md5

    def pkl_file(self):
        return '%s.pkl' % self.md5

    def to_json(self, sort_keys=True, indent=None):
        state = self.__dict__.copy()
        state['rangefinder'] = state['rangefinder'].to_json(sort_keys=sort_keys, indent=indent)
        return json.dumps(state, sort_keys=sort_keys, indent=indent)
