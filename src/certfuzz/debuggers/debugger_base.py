'''
Created on Oct 23, 2012

@organization: cert.org
'''
import logging

from certfuzz.debuggers.errors import DebuggerError


logger = logging.getLogger(__name__)

result_fields = 'debug_crash crash_hash exp faddr output dbg_type'.split()
allowed_exploitability_values = ['UNKNOWN', 'PROBABLY_NOT_EXPLOITABLE',
                                 'PROBABLY_EXPLOITABLE', 'EXPLOITABLE']


class Debugger(object):
    '''
    classdocs
    '''
    _platform = None
    _key = 'debugger'
    _ext = 'debug'

    def __init__(self, program=None, cmd_args=None, outfile_base=None, timeout=None, **options):
        '''
        Default initializer for the base Debugger class.
        '''
        logger.debug('Initialize Debugger')
        self.program = program
        self.cmd_args = cmd_args
        self.outfile = '.'.join((outfile_base, self._ext))
        self.timeout = timeout
        self.input_file = ''
        self.debugger_output = None
        self.result = {}
        self._reset_result()
        self.seed = None
        self.faddr = None
        self.type = self._key
        self.debugger_output = ''
        self.debugheap = False
        logger.debug('DBG OPTS %s', options)

        # turn any other remaining options into attributes
        self.__dict__.update(options)
        logger.debug('DEBUGGER: %s', self.__dict__)

    def _reset_result(self):
        for key in result_fields:
            self.result[key] = None

    def _validate_exploitability(self):
        if not self.result['exp'] in allowed_exploitability_values:
            raise DebuggerError('Unknown exploitability value: %s' % self.result['exp'])

    def outfile_basename(self, basename):
        return '.'.join((basename, self.type))

    def write_output(self, target=None):
        if not target:
            target = self.outfile

        with open(target, 'w') as fd:
            fd.write(self.debugger_output)

    def carve(self, string, token1, token2):
        raise NotImplementedError

    def kill(self, pid, returncode):
        raise NotImplementedError

    def debug(self, input_filename):
        raise NotImplementedError

    def go(self):
        raise NotImplementedError

    def debugger_app(self):
        '''
        Returns the name of the debugger application to use in this class
        '''
        raise NotImplementedError

    def debugger_test(self):
        '''
        Returns a command line (as list) that can be run via subprocess.call
        to confirm whether the debugger is on the path.
        '''
        raise NotImplementedError

    def __enter__(self):
        return self

    def __exit__(self, etype, value, traceback):
        pass

    @property
    def extension(self):
        return self._ext