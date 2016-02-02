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
from certfuzz.runners.errors import RunnerNotFoundError
import shlex
from certfuzz.helpers.misc import quoted

logger = logging.getLogger(__name__)


_zzuf_basename = 'zzuf'
_zzuf_loc = None

_use_cert_version_of_zzuf=False

def check_cert_zzuf():
    #zzuf --help
    # if 'null' in result
    return True

def _find_zzuf():
    global _zzuf_loc
    _zzuf_loc = find_executable(_zzuf_basename)


class ZzufRunner(Runner):
    def __init__(self, options, cmd_template, fuzzed_file, workingdir_base):
        Runner.__init__(self, options, cmd_template, fuzzed_file, workingdir_base)

        self._zzuf_log_basename = 'zzuf_log.txt'
        self.zzuf_log_path = os.path.join(self.workingdir, self._zzuf_log_basename)
        self._quiet = options.get('hideoutput', True)

        self._cmd_template = cmd_template
        self._cmd = self._cmd_template.substitute(SEEDFILE=quoted(fuzzed_file))
        self._cmd_parts = shlex.split(self._cmd)
        self._cmd_parts[0] = os.path.expanduser(self._cmd_parts[0])

        self._zzuf_args = None
        self._construct_zzuf_args()
        logger.debug('_zzuf_args=%s', self._zzuf_args)

    def _construct_zzuf_args(self):
        if _zzuf_loc is None:
            _find_zzuf()
        # if it's still None, we have a problem
        if _zzuf_loc is None:
            raise RunnerNotFoundError('Unable to locate {}, $PATH={}'.format(_zzuf_basename, os.environ['PATH']))

        args = [_zzuf_loc]
        if self._quiet:
            args.append('--quiet')
            
        _opmode='copy'
        if _use_cert_version_of_zzuf:
            _opmode='null'
        
        args.extend(['--signal',
                     '--ratio=0.0',
                     '--seed=0',
                     '--max-crashes=1',
                     '--max-usertime=5.00',
                     '--opmode=%s' % _opmode,
                     '--include=%s' % self.fuzzed_file,
                     ])
        
        
        self._zzuf_args = args

    def _run(self):
        if not len(self._zzuf_args):
            raise RunnerError('_zzuf_args is empty')

        with open(self.fuzzed_file, 'rb') as ff, open(self.zzuf_log_path, 'wb') as zo:
            cmd2run = self._zzuf_args + self._cmd_parts
            logger.debug('RUN_CMD: {}'.format(' '.join(cmd2run)))
            p = subprocess.Popen(cmd2run, cwd=self.workingdir, stdin=ff, stderr=zo)
            rc = p.wait()

            if rc != 0:
                self.saw_crash = True
#                 raise RunnerError('zzuf returncode: {}'.format(rc))

_runner_class=ZzufRunner
