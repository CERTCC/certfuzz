'''
Created on Oct 22, 2014

@author: adh
'''
from certfuzz.runners.runner_base import Runner
from distutils.spawn import find_executable
from certfuzz.runners.errors import RunnerError
import os
import subprocess
import logging
from collections import deque
from certfuzz.runners.errors import RunnerNotFoundError

logger = logging.getLogger(__name__)


class ZzufRunner(Runner):
    def __init__(self, options, cmd_template, fuzzed_file, workingdir_base):
        Runner.__init__(self, options, cmd_template, fuzzed_file, workingdir_base)
        self._zzuf_loc = None
        self._zzuf_args = None
        self._zzuf_log_basename = 'zzuf_log.txt'
        self._zzuf_log = os.path.join(self.workingdir, self._zzuf_log_basename)
        self._quiet = options.get('quiet', True)
        self._zzuf_basename = 'zzuf'

    def _get_zzuf_args(self):
        self._zzuf_args = deque(['--signal',
                          '--ratio=0.0',
                          '--seed=0',
                          '--max-crashes=1',
                          '--max-usertime=5.00',
                          ])

        if self._quiet:
            self._zzuf_args.appendleft('--quiet')

    def _find_zzuf(self):
        self._zzuf_loc = find_executable(self._zzuf_basename)
        if self._zzuf_loc is None:
            raise RunnerNotFoundError('Unable to locate {}, $PATH={}'.format(self._zzuf_basename, os.environ['PATH']))

    def __enter__(self):
        self = Runner.__enter__(self)

        self._find_zzuf()
        self._get_zzuf_args()
        self._zzuf_args.appendleft(self._zzuf_loc)
        logger.debug('_zzuf_args=%s', self._zzuf_args)

        return self

    def _run(self):
        if not len(self._zzuf_args):
            raise RunnerError('_zzuf_args is empty')

        with open(self.fuzzed_file, 'rb') as ff, open(self._zzuf_log, 'ab') as zo:
            p = subprocess.Popen(self._zzuf_args, cwd=self.workingdir, stdin=ff, stderr=zo)
            rc = p.wait()

            if rc != 0:
                raise RunnerError('zzuf returncode: {}'.format(rc))
