'''
Created on Oct 24, 2012

@organization: cert.org
'''
import unittest
from certfuzz.test import misc
import certfuzz.debuggers.output_parsers

class Test(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_api(self):
        module = certfuzz.debuggers.output_parsers
        api_list = ['DebuggerError',
                    'DebuggerFileError',
                    'UnknownDebuggerError',
                    'regex',
                    'DebuggerFile',
                    'detect_format',
                    'check_thread_type',
                    'registers',
                    'blacklist',
                    ]
        (is_fail, msg) = misc.check_for_apis(module, api_list)
        self.assertFalse(is_fail, msg)


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
