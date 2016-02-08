'''
Created on Feb 8, 2016

@author: wd
'''

from certfuzz.runners.runner_base import Runner
from certfuzz.runners.errors import RunnerError

class NullRunner(Runner):
    def __init__(self, options, cmd_template, fuzzed_file, workingdir_base):
        Runner.__init__(self, options, cmd_template, fuzzed_file, workingdir_base)

    def _run(self):
        self.saw_crash = True

_runner_class = NullRunner
