import os
import tempfile
from certfuzz.analyzers.stderr import StdErr

'''
Created on Apr 8, 2011

@organization: cert.org
'''
import unittest
import sys
import string

class Mock(object):
    pass

class Test(unittest.TestCase):
    def delete_file(self, f):
        os.remove(f)
        self.assertFalse(os.path.exists(f))

    def setUp(self):
        (fd, f) = tempfile.mkstemp(text=True)
        os.close(fd)
        self.delete_file(f)
        self.file = '%s.stderr' % f

        cfg = {'runner': {'runtimeout':1},
               'target': {'cmdline_template': string.Template('PROGRAM $SEEDFILE foo')}
               }

        if sys.platform == 'win32':
            cfg['target']['cmdline_tempate'] = string.Template('c:\\cygwin\\bin\\cat.exe -a foo')
        else:
            cfg['target']['cmdline_template'] = string.Template('cat -a foo')


        testcase = Mock()
        testcase.fuzzedfile = Mock()
        testcase.fuzzedfile.path = f
        testcase.fuzzedfile.dirname = os.path.dirname(f)

        self.se = StdErr(cfg, testcase)

    def tearDown(self):
        if os.path.exists(self.file):
            self.delete_file(self.file)
        if os.path.exists(self.se.outfile):
            self.delete_file(self.se.outfile)

    def test_get_stderr(self):
        self.assertFalse(os.path.exists(self.file))
        self.se.go()
        self.assertTrue(os.path.exists(self.file))
        contents = open(self.file, 'r').read()
        self.assertTrue(len(contents) > 0)
        self.assertTrue('option' in contents)
        self.assertTrue('cat' in contents)

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
