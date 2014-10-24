'''
Created on Oct 22, 2014

@author: adh
'''
import subprocess
from certfuzz.fuzzers.fuzzer_base import MinimizableFuzzer
from certfuzz.fuzzers.errors import FuzzerNotFoundError
from distutils.spawn import find_executable
import os


class ZzufFuzzer(MinimizableFuzzer):
    '''
    This fuzzer uses Sam Hocevar's zzuf to mangle self.input and puts the results into
    self.fuzzed'''
    _zzuf_loc = None

    def __enter__(self):
        self = MinimizableFuzzer.__enter__(self)

        self._zzuf_loc = find_executable('zzuf')
        if self._zzuf_loc is None:
            raise FuzzerNotFoundError('Unable to locate zzuf in %s' % os.environ['PATH'])

        return self

    def _fuzz(self):
        self.range = self.sf.rangefinder.next_item()

        zzufargs = [self._zzuf_loc,
                    '--quiet',
                    '--ratio={}:{}'.format(self.range.min, self.range.max),
                    '--seed={}'.format(self.iteration),
                    ]
        p = subprocess.Popen(args=zzufargs, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        (stdoutdata, _stderrdata) = p.communicate(input=self.input)
        self.fuzzed = stdoutdata

_fuzzer_class = ZzufFuzzer
