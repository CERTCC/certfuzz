'''
Created on Feb 12, 2014

@author: adh
'''
import logging
import os

from certfuzz.crash.bff_crash import BffCrash
from certfuzz.file_handlers.basicfile import BasicFile
from certfuzz.fuzztools.ppid_observer import check_ppid
from certfuzz.fuzztools.state_timer import STATE_TIMER
from certfuzz.fuzztools.zzuf import Zzuf
from certfuzz.fuzztools.zzuf import ZzufTestCase
from certfuzz.fuzztools.zzuflog import ZzufLog
from certfuzz.iteration.iteration_base3 import IterationBase3
from certfuzz.testcase_pipeline.tc_pipeline_linux import LinuxTestCasePipeline


logger = logging.getLogger(__name__)


class LinuxIteration(IterationBase3):
    tcpipeline_cls = LinuxTestCasePipeline

    def __init__(self, cfg=None, seednum=None, seedfile=None, r=None, workdirbase=None, quiet=True, uniq_func=None,
                 sf_set=None, rf=None, outdir=None):
        IterationBase3.__init__(self, seedfile, seednum, workdirbase, outdir,
                                sf_set, rf, uniq_func)
        self.cfg = cfg
        self.r = r
        self.quiet_flag = quiet

        self.testcase_base_dir = os.path.join(self.outdir, 'crashers')

        self._zzuf_range = None
        self._zzuf_line = None

        self.pipeline_options = {
                                 'use_valgrind': self.cfg.use_valgrind,
                                 'use_pin_calltrace': self.cfg.use_pin_calltrace,
                                 'minimize_crashers': self.cfg.minimizecrashers,
                                 'minimize_to_string': self.cfg.minimize_to_string,
                                 'uniq_log': self.cfg.uniq_log,
                                 'local_dir': self.cfg.local_dir,
                                 'minimizertimeout': self.cfg.minimizertimeout,
                                 }

    def __enter__(self):
        IterationBase3.__enter__(self)
        check_ppid()
        return self

    def __exit__(self, etype, value, traceback):
        handled = IterationBase3.__exit__(self, etype, value, traceback)

        self.cfg.clean_tmpdir()
        return handled

    def _fuzz(self):
        pass

    def _pre_run(self):
        # do the fuzz
        cmdline = self.cfg.get_command(self.seedfile.path)

        STATE_TIMER.enter_state('fuzzing')
        self.zzuf = Zzuf(self.cfg.local_dir, self.seednum,
            self.seednum,
            cmdline,
            self.seedfile.path,
            self.cfg.zzuf_log_file,
            self.cfg.copymode,
            self.r.min,
            self.r.max,
            self.cfg.progtimeout,
            self.quiet_flag)

    def _run(self):
        self.zzuf.go()

    def _post_run(self):
        STATE_TIMER.enter_state('checking_results')
            # we must have made it through this chunk without a crash
            # so go to next chunk

        self.record_tries()

        if not self.zzuf.saw_crash:
            logger.debug('No crash seen')
            return

        # we must have seen a crash
        # get the results
        zzuf_log = ZzufLog(self.cfg.zzuf_log_file, self.cfg.zzuf_log_out(self.seedfile.output_dir))

        # Don't generate cases for killed process or out-of-memory
        # In the default mode, zzuf will report a signal. In copy (and exit code) mode, zzuf will
        # report the exit code in its output log.  The exit code is 128 + the signal number.
        analysis_needed = zzuf_log.crash_logged(self.cfg.copymode)

        if not analysis_needed:
            return

        # store a few things for use downstream
        self._zzuf_range = zzuf_log.range
        self._zzuf_line = zzuf_log.line
        self._construct_testcase()

    def _construct_testcase(self):
        with ZzufTestCase(seedfile=self.seedfile, seed=self.seednum,
                           range=self._zzuf_range,
                           working_dir=self.working_dir) as ztc:
            ztc.generate()
        fuzzedfile = BasicFile(ztc.outfile)

        logger.info('Building testcase object')
        with BffCrash(cfg=self.cfg,
                            seedfile=self.seedfile,
                            fuzzedfile=fuzzedfile,
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
