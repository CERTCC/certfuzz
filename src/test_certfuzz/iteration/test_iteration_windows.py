'''
Created on Mar 23, 2012

@organization: cert.org
'''

import unittest
from certfuzz.iteration.iteration_windows import WindowsIteration
from test_certfuzz.mocks import MockFuzzer, MockSeedfile, MockRunner, MockCfg
import tempfile
import shutil


class Test(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix='test_iteration_windows_')
        self.workdirbase = tempfile.mkdtemp(
            prefix='workdirbase_', dir=self.tmpdir)
        self.outdir = tempfile.mkdtemp(prefix='outdir_', dir=self.tmpdir)

        _cfg = MockCfg()

        kwargs = {'seedfile': MockSeedfile(),
                  'seednum': 0,
                  'workdirbase': self.workdirbase,
                  'outdir': self.outdir,
                  'sf_set': 'a',
                  'uniq_func': None,
                  'config': _cfg,
                  'fuzzer_cls': MockFuzzer,
                  'runner_cls': MockRunner,
                  'debug': False,
                  }

        self.iteration = WindowsIteration(**kwargs)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def testName(self):
        pass

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
