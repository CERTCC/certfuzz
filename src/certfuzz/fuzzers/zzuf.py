'''
Created on Oct 22, 2014

@author: adh
'''
from certfuzz.fuzzers import Fuzzer
import subprocess


class ZzufFuzzer(Fuzzer):
    '''
    This "fuzzer" copies input_file_path to output_file_path. Useful for
    testing and "refining" a set of crashing test cases through a debugger.
    '''
    def _fuzz(self):
        # run zzuf and put its output in self.fuzzed
        self.range = self.sf.rangefinder.next_item()
        zzufargs = ['zzuf',
                    '--quiet',
                    '--ratio={}:{}'.format(self.range.min, self.range.max),
                    '--seed={}'.format(self.rng_seed),
                    ]
        p = subprocess.Popen(args=zzufargs, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        (stdoutdata, _stderrdata) = p.communicate(input=self.input)
        self.fuzzed = stdoutdata

_fuzzer_class = ZzufFuzzer
