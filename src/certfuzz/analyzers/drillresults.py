'''
Created on Jan 29, 2016

@author: adh
'''
import logging
from certfuzz.analyzers.analyzer_base import Analyzer
from certfuzz.drillresults.testcasebundle_base import TestCaseBundle
from certfuzz.drillresults.errors import TestCaseBundleError

logger=logging.getLogger(__name__)

OUTFILE_EXT = "drillresults"
get_file = lambda x: '%s.%s' % (x, OUTFILE_EXT)


class DrillResults(Analyzer):
    '''
    Drills a bit deeper into results to see how exploitable a testcase might be.
    '''

    def __init__(self, cfg, testcase):
        '''
        Constructor
        '''
        self.cfg = cfg
        self.testcase = testcase
        
        self.outfile = get_file(testcase.fuzzedfile.path)
        self.output_lines = []
    
    
    def _process_tcb(self, tcb):
        details = tcb.details
        score = tcb.score
        crash_key = tcb.crash_hash
        
        output_lines = self.output_lines
        
        output_lines.append('%s - Exploitability rank: %s' % (crash_key, score))
        output_lines.append('Fuzzed file: %s' % details['fuzzedfile'])
        for exception in details['exceptions']:
            shortdesc = details['exceptions'][exception]['shortdesc']
            eiftext = ''
            efa = '0x' + details['exceptions'][exception]['efa']
            if details['exceptions'][exception]['EIF']:
                eiftext = " *** Byte pattern is in fuzzed file! ***"
            output_lines.append('exception %s: %s accessing %s  %s' % (exception, shortdesc, efa, eiftext))
            if details['exceptions'][exception]['instructionline']:
                output_lines.append(details['exceptions'][exception]['instructionline'])
            module = details['exceptions'][exception]['pcmodule']
            if module == 'unloaded':
                if not self.ignore_jit:
                    output_lines.append('Instruction pointer is not in a loaded module!')
            else:
                output_lines.append('Code executing in: %s' % module)

    def _write_outfile(self):
        with open(self.outfile,'wb') as f:
            f.write('\n'.join(self.output_lines))

    def go(self):
        logger.info('Drill Results PLACEHOLDER')

#         return
        # put a list of files in testcasedir
        
        # turn testcase into tescase_bundle
        with TestCaseBundle(dbg_file=dbg_file,
                            testcase_file=self.testcase.fuzzed_file.path,
                            crash_hash=self.testcase.signature,
                            ignore_jit=False) as tcb:
            try:
                tcb.go()
            except TestCaseBundleError as e:
                logger.warning('Skipping drillresults on testcase %s: %s', self.testcase.signature, e)
                return
        
        self._process_tcb(tcb)
        self._write_outfile()
        # if score < max_score do something (more interesting)
        # if score > max_score do something else (less interesting)
        
# 
#             output_blob=tcb.details
#             output_blob['score']=tcb.score
            