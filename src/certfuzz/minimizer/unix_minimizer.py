'''
Created on Oct 9, 2012

@organization: cert.org
'''
from certfuzz.minimizer.minimizer_base import Minimizer as MinimizerBase
import os
from certfuzz.fuzztools.hostinfo import HostInfo

if HostInfo().is_osx():
    from certfuzz.debuggers.crashwrangler import CrashWrangler as debugger_cls
else:
    from certfuzz.debuggers.gdb import GDB as debugger_cls


class UnixMinimizer(MinimizerBase):
    use_watchdog = True
    _debugger_cls = debugger_cls

    def __enter__(self):
        # touch the watchdogfile
        try:
            open(self.watchdogfile, 'w').close()
        except (OSError, IOError) as e:
            # it's okay if we can't, but we should note it
            self.logger.warning('Unable to touch watchdog file %s: %s',
                                self.watchdogfile, e)

        return MinimizerBase.__enter__(self)

    def __exit__(self, etype, value, traceback):
        try:
            os.remove(self.watchdogfile)
        except (OSError, IOError) as e:
            # it's okay if we can't, but we should note it
            self.logger.warning('Unable to remove watchdog file %s: %s',
                                self.watchdogfile, e)
        except AttributeError:
            # self.cfg doesn't have a watchdogfile
            # We probably already logged this fact in __enter__ so we can
            # silently ignore it here
            pass

        return MinimizerBase.__exit__(self, etype, value, traceback)
