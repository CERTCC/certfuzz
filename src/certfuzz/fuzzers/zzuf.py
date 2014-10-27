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
    def _fuzz(self):
        # run zzuf and put its output in self.fuzzed

        zzufloc = find_executable('zzuf')
        if zzufloc is None:
            raise FuzzerNotFoundError('Unable to locate zzuf in %s' % os.environ['PATH'])

        self.range = self.sf.rangefinder.next_item()

        zzufargs = [zzufloc,
                    '--quiet',
                    '--ratio={}:{}'.format(self.range.min, self.range.max),
                    '--seed={}'.format(self.iteration),
                    ]
        p = subprocess.Popen(args=zzufargs, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        (stdoutdata, _stderrdata) = p.communicate(input=self.input)
        self.fuzzed = stdoutdata

_fuzzer_class = ZzufFuzzer
