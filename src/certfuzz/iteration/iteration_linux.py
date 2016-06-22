'''
Created on Feb 12, 2014

@author: adh
'''
import logging
import os

from certfuzz.file_handlers.basicfile import BasicFile
from certfuzz.fuzztools.ppid_observer import check_ppid
from certfuzz.iteration.iteration_base3 import IterationBase3
from certfuzz.tc_pipeline.tc_pipeline_linux import LinuxTestCasePipeline
from certfuzz.helpers.misc import fixup_path
from certfuzz.testcase.testcase_linux import LinuxTestcase


logger = logging.getLogger(__name__)


class LinuxIteration(IterationBase3):
    tcpipeline_cls = LinuxTestCasePipeline

    def __init__(self,
                 seedfile=None,
                 seednum=None,
                 workdirbase=None,
                 outdir=None,
                 sf_set=None,
                 uniq_func=None,
                 config=None,
                 fuzzer_cls=None,
                 runner_cls=None,
                 ):

        IterationBase3.__init__(self,
                                seedfile=seedfile,
                                seednum=seednum,
                                workdirbase=workdirbase,
                                outdir=outdir,
                                sf_set=sf_set,
                                uniq_func=uniq_func,
                                config=config,
                                fuzzer_cls=fuzzer_cls,
                                runner_cls=runner_cls,
                                )

        self.testcase_base_dir = os.path.join(self.outdir, 'crashers')

        self.pipeline_options.update({'use_valgrind': self.cfg['analyzer']['use_valgrind'],
                                      'use_pin_calltrace': self.cfg['analyzer']['use_pin_calltrace'],
                                      'uniq_log': os.path.join(self.cfg['directories']['results_dir'], 'uniquelog.txt'),
                                      'local_dir': fixup_path(self.cfg['directories']['working_dir']),
                                      'minimizertimeout': self.cfg['runoptions']['minimizer_timeout'],
                                      })

    def __enter__(self):
        check_ppid()
        return IterationBase3.__enter__(self)

    def _construct_testcase(self):
        with LinuxTestcase(cfg=self.cfg,
                           seedfile=self.seedfile,
                           fuzzedfile=BasicFile(self.fuzzer.output_file_path),
                           program=self.cfg['target']['program'],
                           cmd_template=self.cmd_template,
                           debugger_timeout=self.cfg['runner']['runtimeout'],
                           backtrace_lines=self.cfg[
                               'debugger']['backtracelevels'],
                           crashers_dir=self.testcase_base_dir,
                           workdir_base=self.working_dir,
                           keep_faddr=self.cfg['runoptions'].get(
                               'keep_unique_faddr', False),
                           save_failed_asserts=self.cfg['analyzer'].get(
                               'savefailedasserts', False),
                           exclude_unmapped_frames=self.cfg['analyzer']['exclude_unmapped_frames']) as testcase:
            # put it on the list for the analysis pipeline
            self.testcases.append(testcase)
