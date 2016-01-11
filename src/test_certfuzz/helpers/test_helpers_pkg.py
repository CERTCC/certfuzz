'''
Created on Oct 24, 2012

@organization: cert.org
'''
import unittest
from test_certfuzz import misc
import certfuzz.helpers

class Test(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_api(self):
        module = certfuzz.helpers
        api_list = ['quoted',
                    'print_dict',
                    'random_str',
                    'bitswap',
                    'log_object',
                    ]
        (is_fail, msg) = misc.check_for_apis(module, api_list)
        self.assertFalse(is_fail, msg)


if __name__ == "__main__":
    unittest.main()
