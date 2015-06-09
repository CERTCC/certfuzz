'''
Created on Oct 9, 2012

@organization: cert.org
'''
from certfuzz.minimizer import Minimizer as MinimizerBase
import os


class UnixMinimizer(MinimizerBase):
    use_watchdog = True

    def __enter__(self):
        # touch the watchdogfile
        try:
            open(self.cfg.watchdogfile, 'w').close()
        except (OSError, IOError) as e:
            # it's okay if we can't, but we should note it
            self.logger.warning('Unable to touch watchdog file %s: %s',
                                self.cfg.watchdogfile, e)
        except AttributeError:
            # self.cfg doesn't have a watchdogfile
            self.logger.info('Config has no watchdogfile attribute, skipping')

        return MinimizerBase.__enter__(self)

    def __exit__(self, etype, value, traceback):
        try:
            os.remove(self.cfg.watchdogfile)
        except (OSError, IOError) as e:
            # it's okay if we can't, but we should note it
            self.logger.warning('Unable to remove watchdog file %s: %s',
                                self.cfg.watchdogfile, e)
        except AttributeError:
            # self.cfg doesn't have a watchdogfile
            # We probably already logged this fact in __enter__ so we can
            # silently ignore it here
            pass

        return MinimizerBase.__exit__(self, etype, value, traceback)
