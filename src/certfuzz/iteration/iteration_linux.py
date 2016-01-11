'''
Created on Feb 12, 2014

@author: adh
'''
import logging
import os

from certfuzz.crash.bff_crash import BffCrash
from certfuzz.file_handlers.basicfile import BasicFile
from certfuzz.fuzztools.ppid_observer import check_ppid
from certfuzz.fuzztools.zzuflog import ZzufLog
from certfuzz.iteration.iteration_base3 import IterationBase3
from certfuzz.testcase_pipeline.tc_pipeline_linux import LinuxTestCasePipeline
from certfuzz.runners.zzufrun import ZzufRunner
from certfuzz.fuzzers.bytemut import ByteMutFuzzer


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
                 cfg=None,
                 fuzzer_cls=None,
                 runner_cls=None,
                 ):

        IterationBase3.__init__(self,
                                seedfile,
                                seednum,
                                workdirbase,
                                outdir,
                                sf_set,
                                uniq_func,
                                cfg,
                                fuzzer_cls,
                                runner_cls,
                                )

        self.quiet_flag = self._iteration_counter < 2

        self.testcase_base_dir = os.path.join(self.outdir, 'crashers')

        self.pipeline_options = {'use_valgrind': self.cfg.use_valgrind,
                                 'use_pin_calltrace': self.cfg.use_pin_calltrace,
                                 'minimize_crashers': self.cfg.minimizecrashers,
                                 'minimize_to_string': self.cfg.minimize_to_string,
                                 'uniq_log': self.cfg.uniq_log,
                                 'local_dir': self.cfg.local_dir,
                                 'minimizertimeout': self.cfg.minimizertimeout,
                                 'minimizable': self.fuzzer_cls.is_minimizable and self.cfg.config['runoptions']['minimize'],
                                 }

    def __enter__(self):
        IterationBase3.__enter__(self)
        check_ppid()
        return self.go

    def _pre_fuzz(self):
        self._fuzz_opts = self.cfg.config['fuzzer']
        IterationBase3._pre_fuzz(self)

    def _pre_run(self):
        self._runner_options = self.cfg.config['runner']

        if self.quiet_flag:
            self._runner_options['hideoutput'] = True
        self._runner_cmd_template = self.cfg.config['target']['cmdline']

        IterationBase3._pre_run(self)

    def _post_run(self):
        if not self.runner.saw_crash:
            logger.debug('No crash seen')
            return

        # we must have seen a crash
        # get the results
        zzuf_log = ZzufLog(self.runner.zzuf_log_path)
        logger.debug("ZzufLog:")
        from pprint import pformat
        for line in pformat(zzuf_log.__dict__).splitlines():
            logger.debug(line)

        # analysis is required in two cases:
        # 1) runner_cls is not defined (self.runner_cls == None)
        # 2) runner_cls is defined, and detects crash (runner_cls.saw_crash == True)
        # this takes care of case 1 by default
        # TODO: does case 1 ever happen?
        analysis_needed = True

        # Don't generate cases for killed process or out-of-memory
        # In the default mode, zzuf will report a signal. In copy (and exit code) mode, zzuf will
        # report the exit code in its output log.  The exit code is 128 + the signal number.
        analysis_needed = zzuf_log.crash_logged(self.cfg.config['zzuf']['copymode'])

        if not analysis_needed:
            return

        self._construct_testcase()

    def _construct_testcase(self):
        logger.info('Building testcase object')
        with BffCrash(cfg=self.cfg,
                      seedfile=self.seedfile,
                      fuzzedfile=BasicFile(self.fuzzer.output_file_path),
                      program=self.cfg.program,
                      debugger_timeout=self.cfg.debugger_timeout,
                      killprocname=self.cfg.killprocname,
                      backtrace_lines=self.cfg.backtracelevels,
                      crashers_dir=self.testcase_base_dir,
                      workdir_base=self.working_dir,
                      seednum=self.seednum,
                      range=self.r) as testcase:
            # put it on the list for the analysis pipeline
            self.testcases.append(testcase)
