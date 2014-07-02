'''
This script looks for interesting crashes and rate them by potential exploitability
'''

import logging
import os

from certfuzz.drillresults.testcasebundle_linux import LinuxTestCaseBundle as TestCaseBundle
from certfuzz.drillresults.result_driller_base import ResultDriller

logger = logging.getLogger(__name__)


class LinuxResultDriller(ResultDriller):
    def _platform_find_testcases(self, crash_hash, files, root):
                # Only use directories that are hashes
        # if "0x" in crash_hash:
            # Create dictionary for hashes in results dictionary
        crasherfile = ''
        # Check each of the files in the hash directory
        for current_file in files:
            # Go through all of the .gdb files and parse them
            if current_file.endswith('.gdb'):
#            if regex['gdb_report'].match(current_file):
                #print 'checking %s' % current_file
                dbg_file = os.path.join(root, current_file)
                logger.debug('found gdb file: %s', dbg_file)
                crasherfile = dbg_file.replace('.gdb', '')
                #crasherfile = os.path.join(root, crasherfile)
                tcb = TestCaseBundle(dbg_file, crasherfile, crash_hash,
                                          self.ignore_jit)
                self.testcase_bundles.append(tcb)
