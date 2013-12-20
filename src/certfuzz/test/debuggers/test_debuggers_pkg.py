'''
Created on Oct 24, 2012

@organization: cert.org
'''
import unittest
from certfuzz.test import misc
import certfuzz.debuggers

class Test(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_api(self):
        module = certfuzz.debuggers
        api_list = ['UndefinedDebuggerError',
                    'DebuggerNotFoundError',
                    'DebuggerError',
                    'get_debug_file',
                    'register',
                    'verify_supported_platform',
                    'get',
                    'result_fields',
                    'allowed_exploitability_values',
                    'Debugger',
                    'debugger',
                    'debug_class',
                    'debug_ext',
                    ]
        (is_fail, msg) = misc.check_for_apis(module, api_list)
        self.assertFalse(is_fail, msg)


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
