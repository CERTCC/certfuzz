'''
Created on Oct 24, 2012

@organization: cert.org
'''
import hashlib
import logging
import string
import tempfile
import os
from certfuzz.file_handlers.basicfile import BasicFile
from certfuzz.config.simple_loader import fixup_config


class Mock(object):

    def __init__(self, *args, **kwargs):
        pass


class MockCrasher(Mock):

    def __init__(self):
        fd, f = tempfile.mkstemp(suffix='.ext', prefix='fileroot')
        os.close(fd)
        self.fuzzedfile = BasicFile(f)
        self.debugger_template = 'foo'

    def set_debugger_template(self, dummy):
        pass


class MockObj(object):

    def __init__(self, **kwargs):
        for (kw, arg) in kwargs:
            self.__setattr__(kw, arg)


class MockCrash(MockObj):

    def __init__(self):
        self.fuzzedfile = MockFile()


class MockFile(MockObj):

    def __init__(self):
        self.dirname = 'dirname'
        self.path = 'path'


class MockRange(Mock):

    def __init__(self):
        self.min = 0.01
        self.max = 0.10

    def __str__(self):
        return '{}-{}'.format(self.min, self.max)


class MockRangefinder(Mock):

    def next_item(self):
        return MockRange()


class MockSeedfile(Mock):
    basename = 'basename'
    root = 'root'
    ext = '.ext'
    tries = 0
    rangefinder = MockRangefinder()

    def __init__(self, sz=1000):
        self.value = 'A' * sz
        self.md5 = hashlib.md5(self.value).hexdigest()
        self.len = len(self.value)

    def read(self):
        return self.value


class MockFuzzedFile(Mock):
    path = 'foo'

    def __init__(self, path=None):
        if path is not None:
            self.path = path


class MockFuzzer(Mock):
    is_minimizable = False


class MockLogger(object):

    def info(self, *args):
        pass


class MockRunner(Mock):
    is_nullrunner = False


class MockTestcase(Mock):
    signature = 'ABCDEFGHIJK'
    logger = logging.getLogger('mocktestcaselogger')
    seedfile = MockSeedfile()
    seednum = 123456789
    range = MockRange()
    fuzzedfile = MockFuzzedFile()
    pc = 'dummyPCstring'
    debugger_extension = 'abcdefg'
    dbg_outfile = 'xyz'
    target_dir = tempfile.mkdtemp()


class MockDbgOut(Mock):
    is_crash = False
    total_stack_corruption = False

    def get_testcase_signature(self, *dummyargs):
        return 'AAAAA'


class MockDebugger(Mock):

    def get(self):
        return MockDebugger

    def go(self):
        return MockDbgOut()


class MockCfg(dict):

    def __init__(self, templated=True):
        self['debugger'] = {'backtracelevels': 5,
                            'debugger': 'gdb',
                            'runtimeout': 10,
                            }
        self['target'] = {'cmdline_template': '$PROGRAM b c d $SEEDFILE',
                          'killprocname': 'a',
                          'program': 'a'}
        self['analyzer'] = {'exclude_unmapped_frames': False,
                            'valgrind_timeout': 1}
        self['directories'] = {'seedfile_dir': '',
                               'results_dir': '',
                               'working_dir': ''}
        self['fuzzer'] = {'fuzzer': 'bytemut'}
        self['campaign'] = {'id': 'xyz'}
        self['runoptions'] = {'first_iteration': 0,
                              'seed_interval': 10,
                              'minimize': True}
        self['runner'] = {'runner': 'zzufrun',
                          'runtimeout': 5}
        if templated:
            self['target']['cmdline_template'] = string.Template(
                self['target']['cmdline_template'])


def MockFixupCfg():
    return fixup_config(MockCfg(templated=False))


class MockMinimizer(object):
    pass
