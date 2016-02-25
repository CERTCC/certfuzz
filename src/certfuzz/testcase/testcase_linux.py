'''
Created on Jul 19, 2011

@organization: cert.org
'''
import logging
import os

from certfuzz.testcase.testcase_base import TestCaseBase
from certfuzz.fuzztools import hostinfo, filetools
from certfuzz.fuzztools.command_line_templating import get_command_args_list
from certfuzz.testcase.errors import TestCaseError

try:
    from certfuzz.analyzers import pin_calltrace
    from certfuzz.analyzers.errors import AnalyzerEmptyOutputError
    from certfuzz.debuggers.output_parsers.calltracefile import Calltracefile
except ImportError:
    pass

logger = logging.getLogger(__name__)

host_info = hostinfo.HostInfo()

if host_info.is_linux():
    from certfuzz.debuggers.gdb import GDB as debugger_cls
elif host_info.is_osx():
    from certfuzz.debuggers.crashwrangler import CrashWrangler as debugger_cls


class LinuxTestcase(TestCaseBase):
    '''
    classdocs
    '''
    _debugger_cls = debugger_cls

    def __init__(self, cfg, seedfile, fuzzedfile, program,
                 debugger_timeout, backtrace_lines,
                 crashers_dir, workdir_base, seednum=None, range=None, keep_faddr=False):
        '''
        Constructor
        '''
        TestCaseBase.__init__(self, seedfile, fuzzedfile, debugger_timeout)
        self.cfg = cfg
        self.program = program
        self.backtrace_lines = backtrace_lines
        self.crash_base_dir = crashers_dir
        self.seednum = seednum
        self.range = range
        self.exclude_unmapped_frames = cfg['analyzer']['exclude_unmapped_frames']
        self.set_debugger_template('bt_only')
        self.keep_uniq_faddr = keep_faddr

        self.cmdargs = None
        self.is_crash = False
        self.signature = None
        self.faddr = None
        self.pc = None
        self.result_dir = None

    def __exit__(self, etype, value, traceback):
        pass

    def set_debugger_template(self, option='bt_only'):
        if host_info.is_linux():
            dbg_template_name = '%s_%s_template.txt' % (self._debugger_cls._key, option)
            self.debugger_template = os.path.join('certfuzz/debuggers/templates', dbg_template_name)
            logger.debug('Debugger template set to %s', self.debugger_template)
            if not os.path.exists(self.debugger_template):
                raise TestCaseError('Debugger template does not exist at %s' % self.debugger_template)

    def update_crash_details(self):
        TestCaseBase.update_crash_details(self)

        cmdlist = get_command_args_list(self.cfg['target']['cmdline_template'],
                                             infile=self.fuzzedfile.path,
                                             posix=True)[1]
        self.cmdargs = cmdlist[1:]
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
        # get debugger output
        logger.debug('Debugger template: %s outfile_base: %s',
                     self.debugger_template, outfile_base)
        debugger_obj = self._debugger_cls(self.program,
                                self.cmdargs,
                                outfile_base,
                                self.debugger_timeout,
                                template=self.debugger_template,
                                exclude_unmapped_frames=self.exclude_unmapped_frames,
                                keep_uniq_faddr=self.keep_uniq_faddr
                                )
        self.dbg = debugger_obj.go()
        self.dbg_file = self.dbg.file


    def confirm_crash(self):
        # get debugger output
        self.get_debug_output(self.fuzzedfile.path)

        if not self.dbg:
            raise TestCaseError('Debug object not found')

        logger.debug('is_crash: %s is_assert_fail: %s', self.dbg.is_crash, self.dbg.is_assert_fail)
        if self.cfg['analyzer']['savefailedasserts']:
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
            self.signature = self.dbg.get_testcase_signature(self.backtrace_lines)
            if self.signature:
                logger.debug("TestCaseBase signature is %s", self.signature)
            else:
                raise TestCaseError('TestCaseBase has no signature.')
            if self.dbg.total_stack_corruption:
                # total_stack_corruption.  Use pin calltrace to get a backtrace
                analyzer_instance = pin_calltrace.Pin_calltrace(self.cfg, self)
                try:
                    analyzer_instance.go()
                except AnalyzerEmptyOutputError:
                    logger.warning('Unexpected empty output from pin. Cannot determine call trace.')
                    return self.signature

                calltrace = Calltracefile(analyzer_instance.outfile)
                pinsignature = calltrace.get_testcase_signature(self.backtrace_lines * 10)
                if pinsignature:
                    self.signature = pinsignature
        return self.signature

    def _verify_crash_base_dir(self):
        if not self.crash_base_dir:
            raise TestCaseError('crash_base_dir not set')

        filetools.mkdir_p(self.crash_base_dir)

    def get_result_dir(self):
        assert self.crash_base_dir
        assert self.signature
        self._verify_crash_base_dir()
        self.result_dir = os.path.join(self.crash_base_dir, self.signature)

        return self.result_dir

