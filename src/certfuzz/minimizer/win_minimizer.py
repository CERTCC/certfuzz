import logging

from certfuzz.fuzztools.filetools import check_zip_file, write_file
from certfuzz.minimizer import Minimizer as MinimizerBase
from certfuzz.minimizer.errors import WindowsMinimizerError


logger = logging.getLogger(__name__)


class WindowsMinimizer(MinimizerBase):
    use_watchdog = False

    def get_signature(self, dbg, backtracelevels):
        # get the basic signature
        crash_hash = MinimizerBase.get_signature(self, dbg, backtracelevels)
        if not crash_hash:
            self.signature = None
        else:
            crash_id_parts = [crash_hash]
            if self.crash.keep_uniq_faddr and hasattr(dbg, 'faddr'):
                crash_id_parts.append(dbg.faddr)
            self.signature = '.'.join(crash_id_parts)
        return self.signature

