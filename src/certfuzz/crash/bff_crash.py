'''
Created on Jul 19, 2011

@organization: cert.org
'''
import logging
import os

from certfuzz.crash.crash_base import Testcase, CrashError
from certfuzz.debuggers import registration
from certfuzz.fuzztools import hostinfo, filetools


try:
    from certfuzz.analyzers import pin_calltrace
    from certfuzz.analyzers import AnalyzerEmptyOutputError
    from certfuzz.debuggers.output_parsers.calltracefile import Calltracefile
except ImportError:
    pass

logger = logging.getLogger(__name__)

debugger = None
host_info = hostinfo.HostInfo()


class BffCrash(Testcase):
    '''
    classdocs
    '''
    tmpdir_pfx = 'bff-crash-'

    def __init__(self, cfg, seedfile, fuzzedfile, program,
                 debugger_timeout, killprocname, backtrace_lines,
                 crashers_dir, workdir_base, seednum=None, range=None, keep_faddr=False):
        '''
        Constructor
        '''
        Testcase.__init__(self, seedfile, fuzzedfile, debugger_timeout)
        self.cfg = cfg
        self.program = program
        self.killprocname = killprocname
        self.backtrace_lines = backtrace_lines
        self.crash_base_dir = crashers_dir
        self.seednum = seednum
        self.range = range
        self.exclude_unmapped_frames = cfg.exclude_unmapped_frames
        self.set_debugger_template('bt_only')
        self.keep_uniq_faddr = keep_faddr

        self.cmdargs = None
#        self.debugger_file = None
        self.is_crash = False
        self.signature = None
        self.faddr = None
        self.pc = None
        self.result_dir = None

    def __exit__(self, etype, value, traceback):
        pass
#        self.clean_tmpdir()

    def set_debugger_template(self, option='bt_only'):
        if host_info.is_linux():
            dbg_template_name = '%s_%s_template.txt' % (registration.debugger, option)
            self.debugger_template = os.path.join(self.cfg.debugger_template_dir, dbg_template_name)
            logger.debug('Debugger template set to %s', self.debugger_template)
            if not os.path.exists(self.debugger_template):
                raise CrashError('Debugger template does not exist at %s' % self.debugger_template)

    def update_crash_details(self):
        Testcase.update_crash_details(self)

        self.cmdargs = self.cfg.get_command_args_list(self.fuzzedfile.path)
#        self.debugger_file = debuggers.get_debug_file(self.fuzzedfile.path)

        self.is_crash = self.confirm_crash()

        if self.is_crash:
            self.signature = self.get_signature()
            self.pc = self.dbg.registers_hex.get(self.dbg.pc_name)
            self.result_dir = self.get_result_dir()
            self.debugger_missed_stack_corruption = self.dbg.debugger_missed_stack_corruption
            self.total_stack_corruption = self.dbg.total_stack_corruption
            self.pc_in_function = self.dbg.pc_in_function
            self.faddr = self.dbg.faddr
            logger.debug('sig: %s', self.signature)
            logger.debug('pc: %s', self.pc)
            logger.debug('result_dir: %s', self.result_dir)
        else:
            # clean up on non-crashes
            self.delete_files()

        return self.is_crash

    def get_debug_output(self, outfile_base):
        # FIXME: does this need to be a global?
        global debugger
        if not debugger:
            debugger = registration.get()
            logger.debug('Got debugger %s', debugger)
        # get debugger output
        logger.debug('Debugger template: %s outfile_base: %s',
                     self.debugger_template, outfile_base)
        debugger_obj = debugger(self.program,
                                self.cmdargs,
                                outfile_base,
                                self.debugger_timeout,
                                self.killprocname,
                                template=self.debugger_template,
                                exclude_unmapped_frames=self.exclude_unmapped_frames,
                                keep_uniq_faddr=self.keep_uniq_faddr
                                )
        self.dbg = debugger_obj.go()

    def confirm_crash(self):
        # get debugger output
        self.get_debug_output(self.fuzzedfile.path)

        if not self.dbg:
            raise CrashError('Debug object not found')

        logger.debug('is_crash: %s is_assert_fail: %s', self.dbg.is_crash, self.dbg.is_assert_fail)
        if self.cfg.savefailedasserts:
            return self.dbg.is_crash
        else:
            # only keep real crashes (not failed assertions)
            return self.dbg.is_crash and not self.dbg.is_assert_fail

    def __repr__(self):
        as_list = ['%s:%s' % (k, v) for (k, v) in self.__dict__.items()]
        return str('\n'.join(as_list))

    def get_signature(self):
        '''
        Runs the debugger on the crash and gets its signature.
        @raise CrasherHasNoSignatureError: if it's a valid crash, but we don't get a signature
        '''
        if not self.signature:
            self.signature = self.dbg.get_crash_signature(self.backtrace_lines)
            if self.signature:
                logger.debug("Testcase signature is %s", self.signature)
            else:
                raise CrashError('Testcase has no signature.')
            if self.dbg.total_stack_corruption:
                # total_stack_corruption.  Use pin calltrace to get a backtrace
                analyzer_instance = pin_calltrace.Pin_calltrace(self.cfg, self)
                try:
                    analyzer_instance.go()
                except AnalyzerEmptyOutputError:
                    logger.warning('Unexpected empty output from pin. Cannot determine call trace.')
                    return self.signature

                calltrace = Calltracefile(analyzer_instance.outfile)
                pinsignature = calltrace.get_crash_signature(self.backtrace_lines * 10)
                if pinsignature:
                    self.signature = pinsignature
        return self.signature

    def _verify_crash_base_dir(self):
        if not self.crash_base_dir:
            raise CrashError('crash_base_dir not set')
        if not os.path.exists(self.crash_base_dir):
            filetools.make_directories(self.crash_base_dir)

    def get_result_dir(self):
        assert self.crash_base_dir
        assert self.signature
        self._verify_crash_base_dir()
        self.result_dir = os.path.join(self.crash_base_dir, self.signature)

        return self.result_dir

    def get_logger(self):
        '''
        sets self.logger to a logger specific to this crash
        '''
        self.logger = logging.getLogger(self.signature)
        if len(self.logger.handlers) == 0:
            if not os.path.exists(self.result_dir):
                logger.error('Result path not found: %s', self.result_dir)
                raise CrashError('Result path not found: {}'.format(self.result_dir))
            logger.debug('result_dir=%s sig=%s', self.result_dir, self.signature)
            logfile = '%s.log' % self.signature
            logger.debug('logfile=%s', logfile)
            logpath = os.path.join(self.result_dir, logfile)
            logger.debug('logpath=%s', logpath)
            hdlr = logging.FileHandler(logpath)
            self.logger.addHandler(hdlr)

        return self.logger
