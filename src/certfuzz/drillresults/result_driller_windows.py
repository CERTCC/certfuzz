'''
This script looks for interesting crashes and rate them by potential exploitability
'''
import logging
import os
import re

from certfuzz.analyzers.drillresults.testcasebundle_windows import WindowsTestCaseBundle as TestCaseBundle
from certfuzz.drillresults.result_driller_base import ResultDriller


logger = logging.getLogger(__name__)

regex = {
    'first_msec': re.compile('^sf_.+-\w+-0x.+.-[A-Z]+.+e0.+'),
}


class WindowsResultDriller(ResultDriller):

    def _platform_find_testcases(self, crash_hash, files, root):
        if "0x" in crash_hash:
            # Create dictionary for hashes in results dictionary
            hash_dict = {}
            hash_dict['hash'] = crash_hash
            crasherfile = ''

            # Check each of the files in the hash directory
            for current_file in files:
                if regex['first_msec'].match(current_file):
                    # If it's exception #0, strip out the exploitability part of
                    # the file name. This gives us the crasher file name
                    crasherfile, _junk = os.path.splitext(current_file)
                    crasherfile = crasherfile.replace('-EXP', '')
                    crasherfile = crasherfile.replace('-PEX', '')
                    crasherfile = crasherfile.replace('-PNE', '')
                    crasherfile = crasherfile.replace('-UNK', '')
                    crasherfile = crasherfile.replace('.e0', '')
                elif current_file.endswith('.drillresults'):
                    # If we have a drillresults file for this crash hash, we use
                    # that output instead of recalculating it
                    # Use the .drillresults output for this crash hash
                    self._load_dr_output(crash_hash,
                                         os.path.join(root, current_file))

            for current_file in files:
                if crash_hash in self.dr_scores:
                    # We are currently working with a crash hash
                    if self.dr_scores[crash_hash] is not None:
                        # We've already got a score for this crash_hash
                        logger.debug('Skipping %s' % current_file)
                        continue

                # Go through all of the .msec files and parse them
                if current_file.endswith('.msec'):
                    dbg_file = os.path.join(root, current_file)
                    if crasherfile and root not in crasherfile:
                        crasherfile = os.path.join(root, crasherfile)
                    with TestCaseBundle(dbg_file, crasherfile, crash_hash,
                                        self.ignore_jit) as tcb:
                        tcb.go()
                        _updated_existing = False
                        for index, tcbundle in enumerate(self.testcase_bundles):
                            if tcbundle.crash_hash == crash_hash:
                                # This is a new exception for the same crash
                                # hash
                                self.testcase_bundles[index].details[
                                    'exceptions'].update(tcb.details['exceptions'])
                                # If the current exception score is lower than
                                # the existing crash_hash score, update it
                                self.testcase_bundles[index].score = min(
                                    self.testcase_bundles[index].score, tcb.score)
                                _updated_existing = True
                        if not _updated_existing:
                            # This is a new crash hash
                            self.testcase_bundles.append(tcb)
