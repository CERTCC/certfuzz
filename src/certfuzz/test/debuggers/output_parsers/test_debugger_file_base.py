'''
Created on Jan 20, 2012

@organization: cert.org
'''

import unittest
import glob
import os
import logging
from certfuzz.debuggers.output_parsers.debugger_file_base import detect_format
from certfuzz.debuggers.output_parsers.errors import UnknownDebuggerError

# logger = logging.getLogger()
# hdlr = logging.StreamHandler()
# logger.addHandler(hdlr)
# logger.setLevel(logging.WARNING)
# debuggers.debug_file.logger.setLevel(logging.DEBUG)

class Test(unittest.TestCase):

    def setUp(self):
        self.btdir = './backtraces'

        self.konqifiles = [os.path.join(self.btdir, f) for f in glob.glob1(self.btdir, 'konqi*')]
        self.abrtfiles = [os.path.join(self.btdir, f) for f in glob.glob1(self.btdir, 'abrt*')]
        self.gdbfiles = [os.path.join(self.btdir, f) for f in glob.glob1(self.btdir, '*.gdb')]

        # files that look like gdb
        self.abrtgdbfiles = [os.path.join(self.btdir, f) for f in glob.glob1(self.btdir, '_abrt*')]

        # files that are expected to raise an exception
        self.expect2fail = [os.path.join(self.btdir, f) for f in glob.glob1(self.btdir, '*fail*')]

    def tearDown(self):
        pass

    def detect_format(self, filelist, expectedtype):
        for f in filelist:
            logger.debug('File: %s', f)
            try:
                detectedtype = detect_format(f)
                self.assertEqual(detectedtype, expectedtype, "File %s: expected: %s got: %s" % (f, expectedtype, detectedtype))
            except UnknownDebuggerError:
                print "Failed to recognize type for %s" % f

    def detect_format_fail(self, filelist):
        for f in filelist:
            self.assertRaises(UnknownDebuggerError, detect_format, f)

    def test_formats_that_should_succeed(self):
        self.detect_format(self.konqifiles, 'konqi')
        self.detect_format(self.gdbfiles, 'gdb')
        self.detect_format(self.abrtfiles, 'abrt')
        self.detect_format(self.abrtgdbfiles, 'gdb')

    def test_formats_that_should_fail(self):
        self.detect_format_fail(self.expect2fail)

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
