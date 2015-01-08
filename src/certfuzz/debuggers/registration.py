'''
Created on Oct 23, 2012

@organization: cert.org
'''
import logging
import os
import platform
import subprocess

from certfuzz.debuggers.errors import UndefinedDebuggerError, \
    DebuggerNotFoundError


logger = logging.getLogger(__name__)

result_fields = 'debug_crash crash_hash exp faddr output dbg_type'.split()
allowed_exploitability_values = ['UNKNOWN', 'PROBABLY_NOT_EXPLOITABLE',
                                 'PROBABLY_EXPLOITABLE', 'EXPLOITABLE']

# remember the system platform (we'll use it a lot)
system = platform.system()

# the keys for debugger_for should match strings returned by platform.system()
debugger_for = {  # platform: key
                 # 'Linux': 'gdb',
                # 'Darwin': 'crashwrangler',
#                'Windows': 'msec',
                }

debugger_class_for = {
                      # key: class
#                      'gdb': GDB,
#                      'crashwrangler': CrashWrangler,
#                      'msec': MsecDebugger,
                      }

debugger_ext = {
                # key: ext
#                'gdb': 'gdb',
#                'crashwrangler': 'cw',
#                'msec': 'msec',
                }

debugger = None
debug_class = None.__class__
debug_ext = None


def register(cls=None):
#    logger.debug('Registering debugger for %s: key=%s class=%s ext=%s',
#                 cls._platform, cls._key, cls.__name__, cls._ext)
    debugger_for[cls._platform] = cls._key
    debugger_class_for[cls._key] = cls
    debugger_ext[cls._key] = cls._ext


def verify_supported_platform():
    global debugger
    global debug_class
    global debug_ext
    # make sure that we're running on a supported platform
    try:
        debugger = debugger_for[system]
        debug_class = debugger_class_for[debugger]
        debug_ext = debugger_ext[debugger]
    except KeyError:
        raise UndefinedDebuggerError(system)

    if not system in debugger_for.keys():
        raise UndefinedDebuggerError(system)

    try:
        dbg = debug_class(None, None, None, None, None)
        with open(os.devnull, 'w') as devnull:
            subprocess.call(dbg.debugger_test(), stderr=devnull,
                            stdout=devnull)
    except OSError:
        raise DebuggerNotFoundError(debugger)
    except TypeError:
        logger.warning('Skipping debugger test for debugger %s', debugger)


def get_debug_file(basename, ext=debug_ext):
    return "%s.%s" % (basename, ext)


def get():
    '''
    Returns a debugger class to be instantiated
    @param system: a string specifying which system you're on
    (output of platform.system())
    '''
    return debug_class
