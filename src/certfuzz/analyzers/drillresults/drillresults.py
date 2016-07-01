'''
Created on Jan 29, 2016

@author: adh
'''
import logging
from certfuzz.analyzers.analyzer_base import Analyzer
from certfuzz.analyzers.drillresults.testcasebundle_base import TestCaseBundle
from certfuzz.drillresults.errors import TestCaseBundleError
from certfuzz.analyzers.drillresults.testcasebundle_linux import LinuxTestCaseBundle
from certfuzz.analyzers.drillresults.testcasebundle_windows import WindowsTestCaseBundle

logger = logging.getLogger(__name__)

OUTFILE_EXT = "drillresults"
get_file = lambda x: '{}.{}'.format(x, OUTFILE_EXT)


class DrillResults(Analyzer):
    '''
    Drills a bit deeper into results to see how exploitable a testcase might be.
    '''
    _tcb_cls = TestCaseBundle

    def __init__(self, cfg, testcase):
        '''
        Constructor
        '''
        self.cfg = cfg
        self.testcase = testcase

        self.outfile = get_file(self.testcase.fuzzedfile.path)
        self.output_lines = []

        # TODO: This should be dynamic, no?
        self.ignore_jit = False

    def _process_tcb(self, tcb):
        details = tcb.details
        score = tcb.score
        crash_key = tcb.crash_hash

        output_lines = []

        output_lines.append(
            '%s - Exploitability rank: %s' % (crash_key, score))
        output_lines.append('Fuzzed file: %s' % details['fuzzedfile'])

        for exception in details['exceptions']:
            shortdesc = details['exceptions'][exception]['shortdesc']
            eiftext = ''
            efa = '0x' + details['exceptions'][exception]['efa']
            if details['exceptions'][exception]['EIF']:
                eiftext = " *** Byte pattern is in fuzzed file! ***"
            output_lines.append(
                'exception %s: %s accessing %s  %s' % (exception, shortdesc, efa, eiftext))
            if details['exceptions'][exception]['instructionline']:
                output_lines.append(
                    details['exceptions'][exception]['instructionline'])
            module = details['exceptions'][exception]['pcmodule']
            if module == 'unloaded':
                if not self.ignore_jit:
                    output_lines.append(
                        'Instruction pointer is not in a loaded module!')
            else:
                output_lines.append('Code executing in: %s' % module)

        self.output_lines = output_lines

    def _write_outfile(self):
        with open(self.outfile, 'w') as f:
            f.write('\n'.join(self.output_lines))

    def go(self):
        # turn testcase into tescase_bundle
        with self._tcb_cls(dbg_outfile=self.testcase.dbg_files[0],
                           testcase_file=self.testcase.fuzzedfile.path,
                           crash_hash=self.testcase.signature,
                           ignore_jit=False) as tcb:
            try:
                tcb.go()
            except TestCaseBundleError as e:
                logger.warning(
                    'Skipping drillresults on testcase %s: %s', self.testcase.signature, e)
                return

            for index, exception in enumerate(self.testcase.dbg_files):
                dbg_file = self.testcase.dbg_files[exception]
                if exception > 0:
                    with self._tcb_cls(dbg_outfile=self.testcase.dbg_files[exception],
                                       testcase_file=self.testcase.fuzzedfile.path,
                                       crash_hash=self.testcase.signature,
                                       ignore_jit=False) as temp_tcb:
                        try:
                            temp_tcb.go()
                        except TestCaseBundleError as e:
                            logger.warning(
                                'Skipping drillresults on testcase %s: %s', self.testcase.signature, e)
                            continue

                        tcb.details['exceptions'].update(
                            temp_tcb.details['exceptions'])

                        tcb.score = min(tcb.score, temp_tcb.score)

        self._process_tcb(tcb)
        self._write_outfile()
        # if score < max_score do something (more interesting)
        # if score > max_score do something else (less interesting)


class LinuxDrillResults(DrillResults):
    _tcb_cls = LinuxTestCaseBundle


class WindowsDrillResults(DrillResults):
    _tcb_cls = WindowsTestCaseBundle
