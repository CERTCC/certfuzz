'''
Created on Aug 1, 2013

@organization: cert.org
'''
import logging

logger = logging.getLogger(__name__)


class IterationBase(object):
    def __init__(self):
        pass

    def __enter__(self):
        pass

    def __exit__(self, etype, value, traceback):
        pass

    def keep_crash(self, crash):
        pass

    def _create_minimizer_cfg(self):
        pass

    def minimize(self, crash):
        pass

    def _copy_seedfile(self):
        pass

    def copy_files(self, crash):
        pass

    def record_success(self):
        pass

    def record_failure(self):
        pass

    def _process_crash(self, crash):
        pass

    def _log_crash(self, crash):
        pass

    def _build_crash(self, fuzzer, cmdlist, dbg_opts, fuzzed_file):
        pass

    def _fuzz_and_run(self):
        pass

    def go(self):
            logger.info('Iteration: %d File: %s', self.current_seed, self.sf.path)
            self._fuzz_and_run()

            # process all the crashes
            for c in self.crashes:
                self._process_crash(c)
