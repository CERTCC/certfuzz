'''
Created on Mar 16, 2011

@organization: cert.org
'''
import json
import os

from certfuzz.file_handlers.basicfile import BasicFile
from certfuzz.file_handlers.errors import SeedFileError
from certfuzz.fuzztools import filetools
from certfuzz.fuzztools.rangefinder import RangeFinder


# TODO: replace with a common function in some helper module
def print_dict(d, indent=0):
    for (k, v) in d.items():
        indent_str = '  ' * indent
        if isinstance(v, dict):
            print(indent_str + k)
            print_dict(v, indent + 1)
        else:
            print(indent_str + "%s (%s): %s" % (k, type(v).__name__, v))


class SeedFile(BasicFile):
    '''
    '''

    def __init__(self, output_base_dir, path):
        '''
        Creates an output dir for this seedfile based on its md5 hash.
        @param output_base_dir: The base directory for output files
        @raise SeedFileError: zero-length files will raise a SeedFileError
        '''
        BasicFile.__init__(self, path)

        if not self.len > 0:
            raise SeedFileError(
                'You cannot do bitwise fuzzing on a zero-length file: %s' % self.path)

        # use len for bytewise, bitlen for bitwise
        if self.len > 1:
            self.range_min = 1.0 / self.len
            self.range_max = 1.0 - self.range_min
        else:
            self.range_min = 0
            self.range_max = 1

        self.tries = 0

        self.rangefinder = RangeFinder(self.range_min, self.range_max)

    def cache_key(self):
        return 'seedfile-%s' % self.md5

    def pkl_file(self):
        return '%s.pkl' % self.md5

    def to_json(self, sort_keys=True, indent=None):
        state = self.__dict__.copy()
        state['rangefinder'] = state['rangefinder'].to_json(
            sort_keys=sort_keys, indent=indent)
        return json.dumps(state, sort_keys=sort_keys, indent=indent)
