'''
This script looks for interesting crashes and rate them by potential exploitability
'''

import logging
import os

from certfuzz.analyzers.drillresults.testcasebundle_darwin import DarwinTestCaseBundle as TestCaseBundle
from certfuzz.drillresults.result_driller_base import ResultDriller

logger = logging.getLogger(__name__)


class DarwinResultDriller(ResultDriller):

    def _platform_find_testcases(self, crash_hash, files, root, force=False):
        # Only use directories that are hashes
        # if "0x" in crash_hash:
        # Create dictionary for hashes in results dictionary
        crasherfile = ''
        # Check each of the files in the hash directory

        for current_file in files:
            # Look for a .drillresults file first.  If there is one, we get the
            # drillresults info from there and move on.
            if current_file.endswith('.drillresults') and not force:
                # Use the .drillresults output for this crash hash
                self._load_dr_output(crash_hash,
                                     os.path.join(root, current_file))
                # Move on to next file
                continue

        for current_file in files:

            if crash_hash in self.dr_scores:
                # We are currently working with a crash hash
                if self.dr_scores[crash_hash] is not None:
                    # We've already got a score for this crash_hash
                    continue

            # Go through all of the .cw files and parse them
            if current_file.endswith('.cw'):
                dbg_file = os.path.join(root, current_file)
                logger.debug('found CrashWrangler file: %s', dbg_file)
                crasherfile = dbg_file.replace('.gmalloc', '')
                crasherfile = crasherfile.replace('.cw', '')
                with TestCaseBundle(dbg_file, crasherfile, crash_hash,
                                    self.ignore_jit) as tcb:
                    tcb.go()
                    self.testcase_bundles.append(tcb)
